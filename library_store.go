// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/alzlib/internal/environment"
	"github.com/hashicorp/go-getter/v2"
)

// LibraryStoreEnabled enables the library store when it is set to true. Setting the
// `ALZLIB_LIBRARY_STORE_ENABLED` environment variable to true also enables it. The store is disabled
// by default.
//
// The library store keeps the libraries that cannot change in `<ALZLIB_DIR>/store`, so that each one
// is downloaded once and then reused, also by other processes that use the same `ALZLIB_DIR`:
//
//   - ALZ Library members, which are fetched at release tags. Release tags are assumed never to move.
//   - Libraries fetched from a go-getter git URL whose `ref` is a full, 40-character, commit SHA.
//
// Other libraries, such as local directories, or git branches and tags, are fetched as when the store
// is disabled. Nothing is removed from the store: delete `<ALZLIB_DIR>/store` to clear it.
var LibraryStoreEnabled atomic.Bool

const (
	libraryStoreDirName        = "store"      // directory of ALZLIB_DIR that holds the library store
	libraryStoreLibDirName     = "lib"        // directory of a store entry that holds the library
	libraryStoreMarkerFileName = "fetch.json" // file of a store entry that describes the entry
	libraryStoreTempDirPattern = "tmp-"       // pattern of the directories in which entries are prepared
	libraryStoreDirPerm        = 0o755
	libraryStoreFilePerm       = 0o644
	// libraryStoreRenameTimeout is how long a failing rename of a new entry is retried on Windows.
	libraryStoreRenameTimeout = 2 * time.Second
	// libraryStoreRenameDelay is the first delay between attempts to rename a new entry on Windows.
	libraryStoreRenameDelay = 10 * time.Millisecond
	// libraryStoreRenameBackoff multiplies the delay between attempts to rename a new entry.
	libraryStoreRenameBackoff = 2
	alzlibModulePath          = "github.com/Azure/alzlib"
	// redactedGetterValue replaces the credentials of a go-getter URL in a store marker.
	redactedGetterValue = "REDACTED"
)

// errLibraryStoreEntryInvalid is returned for a store entry that exists, but does not hold the library
// of the requested URL, as written by this version of the library store.
var errLibraryStoreEntryInvalid = errors.New("library store entry is not valid")

// commitSHARegex matches a full, 40-character, git commit SHA.
var commitSHARegex = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// libraryStoreLocks holds a lock for each store entry, so that the goroutines of this process fetch a
// library into the store one at a time: the first one fetches it, and the others reuse it.
var libraryStoreLocks sync.Map // map[string]chan struct{}

// libraryStoreMarker is the content of the marker file of a store entry. An entry is prepared in a
// temporary directory, which is then renamed to the entry, so an entry with a marker file is complete.
// The marker identifies the URL by its hash, and records it without credentials only: the store can be
// shared, for example in a CI/CD cache, and must not hold the credentials that a URL can contain.
type libraryStoreMarker struct {
	// Getter is the go-getter URL that the library was fetched from, without credentials.
	Getter string `json:"getter"`
	// GetterSHA256 is the SHA-256 hash of the complete go-getter URL that the library was fetched from.
	GetterSHA256 string `json:"getterSha256"`
	// AlzlibVersion is the version of alzlib that fetched the library, if it is known.
	AlzlibVersion string `json:"alzlibVersion,omitempty"`
	// FetchedAt is when the library was fetched.
	FetchedAt time.Time `json:"fetchedAt"`
}

// newLibraryStoreMarker returns the marker of a store entry for the library fetched from getterString.
func newLibraryStoreMarker(getterString string) libraryStoreMarker {
	return libraryStoreMarker{
		Getter:        redactGetterString(getterString),
		GetterSHA256:  sha256Hex(getterString),
		AlzlibVersion: alzlibVersion(),
		FetchedAt:     time.Now().UTC(),
	}
}

// matches reports whether the marker was written for the library fetched from getterString.
func (m libraryStoreMarker) matches(getterString string) bool {
	return m.GetterSHA256 == sha256Hex(getterString)
}

// sha256Hex returns the SHA-256 hash of s, as a hexadecimal string.
func sha256Hex(s string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}

// redactGetterString returns getterString without the credentials that a go-getter URL can contain:
// the user information of the URL, such as `user:token@`, and the value of the `sshkey` parameter,
// which is a private SSH key. Each is replaced with redactedGetterValue.
func redactGetterString(getterString string) string {
	base, rawQuery, hasQuery := strings.Cut(getterString, "?")

	if i := strings.Index(base, "://"); i >= 0 {
		authorityStart := i + len("://")
		authority, _, _ := strings.Cut(base[authorityStart:], "/")

		if at := strings.LastIndex(authority, "@"); at >= 0 {
			base = base[:authorityStart] + redactedGetterValue + base[authorityStart+at:]
		}
	}

	if !hasQuery {
		return base
	}

	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return base + "?" + redactedGetterValue
	}

	for key := range query {
		if strings.EqualFold(key, "sshkey") {
			query.Set(key, redactedGetterValue)
		}
	}

	return base + "?" + query.Encode()
}

// alzlibVersion returns the version of the alzlib module in this program, if it is known.
var alzlibVersion = sync.OnceValue(func() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	if info.Main.Path == alzlibModulePath {
		return info.Main.Version
	}

	for _, dep := range info.Deps {
		if dep.Path == alzlibModulePath {
			return dep.Version
		}
	}

	return ""
})

// libraryStoreEnabled reports whether the library store is enabled, by LibraryStoreEnabled or by the
// `ALZLIB_LIBRARY_STORE_ENABLED` environment variable.
func libraryStoreEnabled() bool {
	return LibraryStoreEnabled.Load() || environment.LibraryStoreEnabled()
}

// isPinnedGitSource reports whether go-getter fetches getterString with git, at a full commit SHA, so
// that the library cannot change.
func isPinnedGitSource(getterString string) bool {
	_, rawQuery, ok := strings.Cut(getterString, "?")
	if !ok {
		return false
	}

	query, err := url.ParseQuery(rawQuery)
	if err != nil || !commitSHARegex.MatchString(query.Get("ref")) {
		return false
	}

	// Only git uses the ref parameter: other getters, such as http, pass it on to the server.
	for _, g := range getter.Getters {
		if _, isGit := g.(*getter.GitGetter); !isGit {
			continue
		}

		detected, err := getter.Detect(&getter.Request{Src: getterString}, g)

		return err == nil && detected
	}

	return false
}

// fetchLibraryIntoStore returns the library at getterString from its entry in the library store,
// `<ALZLIB_DIR>/store/<hash of getterString>`, and fetches it first if the entry does not exist.
// The library and the marker file are written to a temporary directory of the store, which is then
// renamed to the entry: other processes see either no entry or a complete one. If another process
// adds the entry first, the library of that entry is returned.
// It returns errLibraryStoreEntryInvalid if the entry exists but is not complete for getterString.
func fetchLibraryIntoStore(ctx context.Context, getterString string) (fs.FS, error) {
	storeDir := filepath.Join(environment.AlzLibDir(), libraryStoreDirName)
	entryDir := filepath.Join(storeDir, hashStr(getterString))
	libDir := filepath.Join(entryDir, libraryStoreLibDirName)

	unlock, err := lockLibraryStoreEntry(ctx, entryDir)
	if err != nil {
		return nil, err
	}

	defer unlock()

	if libraryStoreEntryComplete(entryDir, getterString) {
		return os.DirFS(libDir), nil
	}

	if _, err := os.Lstat(entryDir); err == nil {
		return nil, fmt.Errorf("%w: %s", errLibraryStoreEntryInvalid, entryDir)
	}

	if err := os.MkdirAll(storeDir, libraryStoreDirPerm); err != nil {
		return nil, fmt.Errorf(
			"FetchLibraryByGetterString: error creating library store directory %s: %w",
			storeDir,
			err,
		)
	}

	tmpDir, err := os.MkdirTemp(storeDir, libraryStoreTempDirPattern)
	if err != nil {
		return nil, fmt.Errorf(
			"FetchLibraryByGetterString: error creating temporary directory in library store %s: %w",
			storeDir,
			err,
		)
	}

	// Once tmpDir has been renamed to entryDir, there is nothing left to remove.
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := prepareLibraryStoreEntry(ctx, getterString, tmpDir); err != nil {
		return nil, err
	}

	if err := renameLibraryStoreEntry(ctx, tmpDir, entryDir); err != nil {
		if libraryStoreEntryComplete(entryDir, getterString) {
			// Another process added the entry first.
			return os.DirFS(libDir), nil
		}

		return nil, fmt.Errorf(
			"FetchLibraryByGetterString: error adding library %s to library store entry %s: %w",
			getterString,
			entryDir,
			err,
		)
	}

	return os.DirFS(libDir), nil
}

// prepareLibraryStoreEntry fetches the library at getterString into the store entry that is prepared
// in dir, and writes the marker file of the entry.
func prepareLibraryStoreEntry(ctx context.Context, getterString, dir string) error {
	// os.MkdirTemp creates a directory that only its owner can read.
	if err := os.Chmod(dir, libraryStoreDirPerm); err != nil {
		return fmt.Errorf("FetchLibraryByGetterString: error setting permissions of %s: %w", dir, err)
	}

	if err := downloadLibrary(ctx, getterString, filepath.Join(dir, libraryStoreLibDirName)); err != nil {
		return err
	}

	marker, err := json.MarshalIndent(newLibraryStoreMarker(getterString), "", "  ")
	if err != nil {
		return fmt.Errorf("FetchLibraryByGetterString: error encoding library store marker: %w", err)
	}

	markerFile := filepath.Join(dir, libraryStoreMarkerFileName)
	if err := os.WriteFile(markerFile, marker, libraryStoreFilePerm); err != nil {
		return fmt.Errorf(
			"FetchLibraryByGetterString: error writing library store marker %s: %w",
			markerFile,
			err,
		)
	}

	return nil
}

// libraryStoreEntryComplete reports whether the store entry entryDir holds the library fetched from
// getterString.
func libraryStoreEntryComplete(entryDir, getterString string) bool {
	data, err := os.ReadFile(filepath.Join(entryDir, libraryStoreMarkerFileName))
	if err != nil {
		return false
	}

	var marker libraryStoreMarker
	if err := json.Unmarshal(data, &marker); err != nil || !marker.matches(getterString) {
		return false
	}

	info, err := os.Stat(filepath.Join(entryDir, libraryStoreLibDirName))

	return err == nil && info.IsDir()
}

// renameLibraryStoreEntry renames the prepared store entry tmpDir to entryDir, and fails if entryDir
// exists. On Windows, renaming a directory also fails while another process, such as a virus scanner
// that checks the new files, has a file in it open. There, the rename is retried for up to
// libraryStoreRenameTimeout, as the Go command does for its module cache, until entryDir exists.
func renameLibraryStoreEntry(ctx context.Context, tmpDir, entryDir string) error {
	deadline := time.Now().Add(libraryStoreRenameTimeout)
	delay := libraryStoreRenameDelay

	for {
		err := os.Rename(tmpDir, entryDir)
		if err == nil || runtime.GOOS != "windows" {
			return err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return err
		}

		if _, statErr := os.Lstat(entryDir); statErr == nil {
			return err
		}

		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(min(delay, remaining)):
		}

		delay *= libraryStoreRenameBackoff
	}
}

// lockLibraryStoreEntry waits until no other goroutine of this process holds the lock of the store
// entry entryDir, takes the lock, and returns the function that releases it.
func lockLibraryStoreEntry(ctx context.Context, entryDir string) (func(), error) {
	lock, _ := libraryStoreLocks.LoadOrStore(entryDir, make(chan struct{}, 1))
	ch := lock.(chan struct{})

	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"FetchLibraryByGetterString: error waiting for library store entry %s: %w",
			entryDir,
			ctx.Err(),
		)
	}
}
