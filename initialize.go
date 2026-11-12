// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/Azure/alzlib/internal/environment"
	"github.com/Azure/alzlib/internal/processor"
	"github.com/hashicorp/go-getter/v2"
)

// Instance is used to track the current instance ID.
// When set by the caller, it prevents collisions in the .alzlib directory.
var Instance atomic.Uint32

// maxConcurrentLibraryFetches is the maximum number of libraries that FetchWithDependencies fetches at
// the same time.
const maxConcurrentLibraryFetches = 4

// prefetchableLibraryReference is implemented by the library references of this package. Their Fetch
// method keeps the filesystem that it fetched, so a prefetched reference is not fetched again, and they
// can take the filesystem that was fetched for another reference to the same library.
type prefetchableLibraryReference interface {
	LibraryReference
	setFS(filesystem fs.FS)
}

// fetchLibrariesWithDependencies fetches libs and all of their dependencies. The result lists each
// library (by String()) once, after its dependencies, in the order of a depth-first walk of libs and
// their dependencies. This order decides which library overwrites another one when overwriting is
// allowed, so it must not depend on the order in which concurrent fetches complete:
//
//  1. prefetchLibraries fetches the libraries and their dependencies concurrently.
//  2. libraryWalk walks the libraries as they were walked before they were prefetched. It uses the
//     prefetched filesystems, and fetches anything that was not prefetched, so it returns the same
//     libraries and errors as before.
//
// The destination directory of each library is the hash of the library reference, appended to the
// `<ALZLIB_DIR>/<Instance>` directory, unless the library is in the library store.
// On error, the libraries added so far are returned with the error.
func fetchLibrariesWithDependencies(
	ctx context.Context,
	libs ...LibraryReference,
) (LibraryReferences, error) {
	walk := libraryWalk{
		prefetched: prefetchLibraries(ctx, libs),
		processed:  make(map[string]bool),
		inProgress: make(map[string]bool),
		result:     make(LibraryReferences, 0, InitialLibraryReferencesCapacity),
	}

	for _, lib := range libs {
		if err := walk.visit(ctx, lib); err != nil {
			return walk.result, err
		}
	}

	return walk.result, nil
}

// libraryWalk is the depth-first walk of fetchLibrariesWithDependencies.
type libraryWalk struct {
	prefetched map[string]fs.FS // filesystems fetched by prefetchLibraries, by library
	processed  map[string]bool  // libraries added to result
	inProgress map[string]bool  // libraries whose dependencies are being walked
	result     LibraryReferences
}

// visit fetches lib and its dependencies, and adds them to the result after their dependencies.
func (w *libraryWalk) visit(ctx context.Context, lib LibraryReference) error {
	key := lib.String()
	if w.processed[key] {
		return nil
	}

	if w.inProgress[key] {
		return fmt.Errorf("FetchLibraryWithDependencies: circular dependency on library %s", key)
	}

	w.inProgress[key] = true
	defer delete(w.inProgress, key)

	f, err := w.fetch(ctx, lib)
	if err != nil {
		return fmt.Errorf(
			"FetchLibraryWithDependencies: error fetching library %s: %w",
			key,
			err,
		)
	}

	pscl := processor.NewClient(f)

	libmeta, err := pscl.Metadata()
	if err != nil {
		return fmt.Errorf(
			"FetchLibraryWithDependencies: error getting metadata for library %s: %w",
			key,
			err,
		)
	}

	meta := NewMetadata(libmeta, lib)
	// for each dependency, recurse using this function
	for _, dep := range meta.Dependencies() {
		if err := w.visit(ctx, dep); err != nil {
			return fmt.Errorf(
				"FetchLibraryWithDependencies: error fetching dependencies for library %s: %w",
				key,
				err,
			)
		}
	}
	// add the current library reference to the list
	w.result = append(w.result, lib)
	w.processed[key] = true

	return nil
}

// fetch returns the filesystem of lib. A reference without a filesystem takes the filesystem that was
// prefetched for the same library: its own fetch would have used the same destination directory.
func (w *libraryWalk) fetch(ctx context.Context, lib LibraryReference) (fs.FS, error) {
	if p, ok := lib.(prefetchableLibraryReference); ok && p.FS() == nil {
		if f, ok := w.prefetched[p.String()]; ok {
			p.setFS(f)
		}
	}

	return lib.Fetch(ctx, hash(lib))
}

// prefetchLibraries fetches libs and their dependencies, at most maxConcurrentLibraryFetches at a time,
// and returns the filesystems that it fetched, by library (String()). Each library is prefetched once,
// with the first reference to it that is found. Only the library references of this package are
// prefetched: the Fetch method of other implementations might fetch again when the walk calls it.
// Errors are ignored: the walk fetches a library that was not prefetched, and reports its error.
func prefetchLibraries(ctx context.Context, libs LibraryReferences) map[string]fs.FS {
	var (
		mu         sync.Mutex
		wg         sync.WaitGroup
		seen       = make(map[string]bool)
		prefetched = make(map[string]fs.FS)
		slots      = make(chan struct{}, maxConcurrentLibraryFetches)
	)

	var prefetch func(lib LibraryReference)

	prefetch = func(lib LibraryReference) {
		p, ok := lib.(prefetchableLibraryReference)
		if !ok {
			return
		}

		key := p.String()

		mu.Lock()

		if seen[key] {
			mu.Unlock()
			return
		}

		seen[key] = true

		mu.Unlock()

		wg.Go(func() {
			f, fetched := prefetchLibrary(ctx, p, slots)
			if f == nil {
				return
			}

			if fetched {
				mu.Lock()
				prefetched[key] = f
				mu.Unlock()
			}

			libmeta, err := processor.NewClient(f).Metadata()
			if err != nil {
				return
			}

			for _, dep := range NewMetadata(libmeta, p).Dependencies() {
				prefetch(dep)
			}
		})
	}

	for _, lib := range libs {
		prefetch(lib)
	}

	wg.Wait()

	return prefetched
}

// prefetchLibrary returns the filesystem of lib, and whether it fetched lib to get it. A reference that
// already has a filesystem, for example one created with NewCustomLibraryReferenceFromFS, is not
// fetched, and its filesystem is not used for other references to the same library, as these fetch
// the library themselves. It returns a nil filesystem if lib could not be fetched. slots limits the
// number of concurrent fetches.
func prefetchLibrary(
	ctx context.Context,
	lib prefetchableLibraryReference,
	slots chan struct{},
) (fs.FS, bool) {
	if f := lib.FS(); f != nil {
		return f, false
	}

	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}

	defer func() { <-slots }()

	f, err := lib.Fetch(ctx, hash(lib))
	if err != nil {
		return nil, false
	}

	return f, true
}

// hash returns the SHA224 hash of a fmt.Stringer, as a string.
func hash(s fmt.Stringer) string {
	return hashStr(s.String())
}

// hash returns the SHA224 hash of a string, as a string.
func hashStr(s string) string {
	return fmt.Sprintf("%x", sha256.Sum224([]byte(s)))
}

// FetchAzureLandingZonesLibraryMember is a convenience function to fetch the Azure Landing Zones
// library by member path
// and tag (ref).
// It calls FetchLibraryByGetterString with the appropriate URL.
// The destination directory will be appended to the `.alzlib` directory in the current working
// directory.
// This can be override by setting the `ALZLIB_DIR` environment variable.
// If the library store is enabled (see LibraryStoreEnabled), the member is fetched into the store, or
// reused from it, instead: ALZ Library members are fetched at release tags, which are assumed not to
// move.
// To fetch the ALZ reference, supply "platform/alz" as the member, with the tag (e.g. 2024.03.03).
func FetchAzureLandingZonesLibraryMember(
	ctx context.Context,
	path, ref, dstDir string,
) (fs.FS, error) {
	return fetchLibrary(ctx, alzLibraryMemberGetterString(path, ref), dstDir, true)
}

// alzLibraryMemberGetterString returns the go-getter URL of the ALZ Library member at path, at the
// release tag ref.
func alzLibraryMemberGetterString(path, ref string) string {
	q := url.Values{}
	q.Add("ref", fmt.Sprintf("%s/%s", path, ref))

	return fmt.Sprintf("git::%s//%s?%s", environment.AlzLibraryGitURL(), path, q.Encode())
}

// FetchLibraryByGetterString fetches a library from a URL using the go-getter library.
// The caller must supply a valid go-getter URL and a destination directory, which will be appended
// to
// the `.alzlib` directory in the current working directory.
// This can be override by setting the `ALZLIB_DIR` environment variable.
// If the library store is enabled (see LibraryStoreEnabled) and the URL is a git URL whose `ref` is a
// full commit SHA, the library is fetched into the store, or reused from it, instead.
// It returns an fs.FS interface to the fetched library to be used in the AlzLib.Init() method.
func FetchLibraryByGetterString(ctx context.Context, getterString, dstDir string) (fs.FS, error) {
	return fetchLibrary(ctx, getterString, dstDir, isPinnedGitSource(getterString))
}

// fetchLibrary fetches the library at getterString. If immutable is true, the library cannot change,
// and it is fetched into the library store, or reused from it, when the store is enabled. Otherwise
// it is fetched to `<ALZLIB_DIR>/<Instance>/<dstDir>`, replacing what is there.
func fetchLibrary(ctx context.Context, getterString, dstDir string, immutable bool) (fs.FS, error) {
	if immutable && libraryStoreEnabled() {
		f, err := fetchLibraryIntoStore(ctx, getterString)
		if !errors.Is(err, errLibraryStoreEntryInvalid) {
			return f, err
		}
		// The store entry exists but is not complete for getterString. It is left as it is, as another
		// process might be using it, and the library is fetched as if the store was disabled.
	}

	return fetchLibraryToInstanceDir(ctx, getterString, dstDir)
}

// fetchLibraryToInstanceDir fetches the library at getterString to `<ALZLIB_DIR>/<Instance>/<dstDir>`,
// replacing what is there.
func fetchLibraryToInstanceDir(ctx context.Context, getterString, dstDir string) (fs.FS, error) {
	baseDir := environment.AlzLibDir()
	instance := strconv.Itoa(int(Instance.Load()))
	dst := filepath.Join(baseDir, instance, dstDir)

	if err := os.RemoveAll(dst); err != nil {
		return nil, fmt.Errorf(
			"FetchLibraryByGetterString: error cleaning destination directory %s: %w",
			dst,
			err,
		)
	}

	if err := downloadLibrary(ctx, getterString, dst); err != nil {
		return nil, err
	}

	return os.DirFS(dst), nil
}

// downloadLibrary downloads the library at getterString to the directory dst, using go-getter.
// Relative paths are relative to the working directory.
// It is a variable so that tests can observe downloads.
var downloadLibrary = func(ctx context.Context, getterString, dst string) error {
	client := getter.Client{
		DisableSymlinks: true,
	}

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("FetchLibraryByGetterString: error getting working directory: %w", err)
	}

	req := &getter.Request{
		Src: getterString,
		Dst: dst,
		Pwd: wd,
	}

	if _, err := client.Get(ctx, req); err != nil {
		return fmt.Errorf(
			"FetchLibraryByGetterString: error fetching library. source `%s`, destination `%s`, wd `%s`: %w",
			getterString,
			dst,
			wd,
			err,
		)
	}

	return nil
}
