// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAlzMemberPath          = "platform/alz"
	testAlzMemberRef           = "2026.01.0"
	testLibraryMetadataFile    = "alz_library_metadata.json"
	testLibraryMetadata        = `{"name": "test", "display_name": "test", "description": "test"}`
	testLibraryStoreHelperEnv  = "ALZLIB_TEST_LIBRARY_STORE_HELPER"
	testLibraryStoreProcesses  = 3
	testLibraryStoreGoroutines = 8
	testOpenFileDuration       = 200 * time.Millisecond
)

// runGit runs git in dir, without signing commits or tags, and returns its trimmed output.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	args = append([]string{
		"-c", "user.name=alzlib", "-c", "user.email=alzlib@example.com",
		"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
	}, args...)
	cmd := exec.Command("git", args...)
	cmd.Dir = dir

	out, err := cmd.Output()
	if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) {
		t.Fatalf("git %v: %v: %s", args, err, exitErr.Stderr)
	}

	require.NoError(t, err)

	return strings.TrimSpace(string(out))
}

// newTestLibraryRepo creates a git repository with files, commits them, and returns the directory of
// the repository and the commit SHA. It skips the test if git is not installed.
func newTestLibraryRepo(t *testing.T, files map[string]string) (string, string) {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	dir := t.TempDir()
	runGit(t, dir, "init", "--quiet")

	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), libraryStoreDirPerm))
		require.NoError(t, os.WriteFile(path, []byte(content), libraryStoreFilePerm))
	}

	runGit(t, dir, "add", "--all")
	runGit(t, dir, "commit", "--quiet", "--message", "library")

	return dir, runGit(t, dir, "rev-parse", "HEAD")
}

// fileURL returns the file URL of the directory dir.
func fileURL(dir string) string {
	path := filepath.ToSlash(dir)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return "file://" + path
}

// newTestAlzLibrary creates a git repository in place of the ALZ Library, with the member
// testAlzMemberPath at the release testAlzMemberRef, and points ALZLIB_LIBRARY_GIT_URL to it.
func newTestAlzLibrary(t *testing.T) {
	t.Helper()

	dir, _ := newTestLibraryRepo(t, map[string]string{
		testAlzMemberPath + "/" + testLibraryMetadataFile: testLibraryMetadata,
	})
	runGit(t, dir, "tag", testAlzMemberPath+"/"+testAlzMemberRef)
	t.Setenv("ALZLIB_LIBRARY_GIT_URL", fileURL(dir))
}

// useLibraryStore points ALZLIB_DIR to a new directory, which it returns, and enables the library store
// until the end of the test.
func useLibraryStore(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("ALZLIB_DIR", dir)
	t.Setenv("ALZLIB_LIBRARY_STORE_ENABLED", "")
	LibraryStoreEnabled.Store(true)
	t.Cleanup(func() { LibraryStoreEnabled.Store(false) })

	return dir
}

// observeDownloads replaces downloadLibrary until the end of the test with a function that counts the
// downloads and then calls after, if it is not nil, with the result of the download.
func observeDownloads(
	t *testing.T,
	after func(getterString, dst string, err error) error,
) *atomic.Int32 {
	t.Helper()

	var count atomic.Int32

	download := downloadLibrary
	downloadLibrary = func(ctx context.Context, getterString, dst string) error {
		count.Add(1)

		err := download(ctx, getterString, dst)
		if after != nil {
			return after(getterString, dst, err)
		}

		return err
	}

	t.Cleanup(func() { downloadLibrary = download })

	return &count
}

// libraryStoreEntry returns the store entry directory of getterString.
func libraryStoreEntry(alzlibDir, getterString string) string {
	return filepath.Join(alzlibDir, libraryStoreDirName, hashStr(getterString))
}

// instanceDir returns the directory that libraries are fetched to when they are not in the store.
func instanceDir(alzlibDir string) string {
	return filepath.Join(alzlibDir, strconv.Itoa(int(Instance.Load())))
}

// requireLibraryFile checks that the library libFS has the file name.
func requireLibraryFile(t *testing.T, libFS fs.FS, name string) {
	t.Helper()
	require.NotNil(t, libFS)

	_, err := fs.Stat(libFS, name)
	require.NoError(t, err)
}

func TestIsPinnedGitSource(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"

	cases := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "git commit", source: "git::https://example.com/repo.git//lib?ref=" + sha, want: true},
		{name: "github commit", source: "github.com/org/repo//lib?ref=" + sha, want: true},
		{name: "upper case commit", source: "git::https://example.com/repo.git?ref=" + strings.ToUpper(sha), want: true},
		{name: "other parameters", source: "git::https://example.com/repo.git?depth=1&ref=" + sha, want: true},
		{name: "git tag", source: "git::https://example.com/repo.git//lib?ref=v1.0.0", want: false},
		{name: "short commit", source: "git::https://example.com/repo.git?ref=" + sha[:7], want: false},
		{name: "no ref", source: "git::https://example.com/repo.git//lib", want: false},
		{name: "http", source: "https://example.com/lib.zip?ref=" + sha, want: false},
		{name: "local directory", source: "./lib?ref=" + sha, want: false},
		{name: "alz library member", source: alzLibraryMemberGetterString(testAlzMemberPath, testAlzMemberRef), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isPinnedGitSource(tc.source))
		})
	}
}

func TestRedactGetterString(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"

	cases := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "no credentials",
			source: "git::https://example.com/repo.git//lib?ref=" + sha,
			want:   "git::https://example.com/repo.git//lib?ref=" + sha,
		},
		{
			name:   "user and password",
			source: "git::https://user:secret@example.com/repo.git//lib?ref=" + sha,
			want:   "git::https://REDACTED@example.com/repo.git//lib?ref=" + sha,
		},
		{
			name:   "token as user",
			source: "git::https://secret@example.com/repo.git?ref=" + sha,
			want:   "git::https://REDACTED@example.com/repo.git?ref=" + sha,
		},
		{
			name:   "ssh key",
			source: "git::ssh://git@example.com/repo.git?ref=" + sha + "&sshkey=c2VjcmV0",
			want:   "git::ssh://REDACTED@example.com/repo.git?ref=" + sha + "&sshkey=REDACTED",
		},
		{
			name:   "scp-like ssh",
			source: "git::git@example.com:org/repo.git?ref=" + sha,
			want:   "git::git@example.com:org/repo.git?ref=" + sha,
		},
		{
			name:   "invalid query",
			source: "git::https://example.com/repo.git?ref=%zz&sshkey=c2VjcmV0",
			want:   "git::https://example.com/repo.git?REDACTED",
		},
		{
			name:   "local directory",
			source: "./lib",
			want:   "./lib",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, redactGetterString(tc.source))
		})
	}
}

// TestLibraryStoreMarkerHasNoCredentials checks that the marker of a store entry does not hold the
// credentials of the URL, and still identifies the URL.
func TestLibraryStoreMarkerHasNoCredentials(t *testing.T) {
	const getterString = "git::https://user:pa55word@example.com/repo.git//lib?" +
		"ref=0123456789abcdef0123456789abcdef01234567&sshkey=c3NoLWtleQ"

	data, err := json.Marshal(newLibraryStoreMarker(getterString))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "pa55word")
	assert.NotContains(t, string(data), "c3NoLWtleQ")

	var marker libraryStoreMarker
	require.NoError(t, json.Unmarshal(data, &marker))
	assert.True(t, marker.matches(getterString))
	assert.False(t, marker.matches(strings.Replace(getterString, "pa55word", "other", 1)))
}

// TestLibraryStoreAlzLibraryMember checks that an ALZ Library member is fetched into the store once,
// and reused by later fetches.
func TestLibraryStoreAlzLibraryMember(t *testing.T) {
	newTestAlzLibrary(t)
	alzlibDir := useLibraryStore(t)
	downloads := observeDownloads(t, nil)
	ctx := context.Background()

	libFS, err := NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef).Fetch(ctx, "dst")
	require.NoError(t, err)
	requireLibraryFile(t, libFS, testLibraryMetadataFile)
	assert.Equal(t, int32(1), downloads.Load())

	getterString := alzLibraryMemberGetterString(testAlzMemberPath, testAlzMemberRef)
	entryDir := libraryStoreEntry(alzlibDir, getterString)
	assert.True(t, libraryStoreEntryComplete(entryDir, getterString))

	data, err := os.ReadFile(filepath.Join(entryDir, libraryStoreMarkerFileName))
	require.NoError(t, err)

	var marker libraryStoreMarker
	require.NoError(t, json.Unmarshal(data, &marker))
	assert.Equal(t, getterString, marker.Getter)
	assert.True(t, marker.matches(getterString))
	assert.False(t, marker.FetchedAt.IsZero())

	// A new reference to the member, in another instance, reuses the entry.
	instance := Instance.Load()
	Instance.Store(instance + 1)
	t.Cleanup(func() { Instance.Store(instance) })

	libFS, err = NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef).Fetch(ctx, "dst")
	require.NoError(t, err)
	requireLibraryFile(t, libFS, testLibraryMetadataFile)
	assert.Equal(t, int32(1), downloads.Load())

	// The library is only in the store, and no temporary directory is left.
	entries, err := os.ReadDir(alzlibDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, libraryStoreDirName, entries[0].Name())

	entries, err = os.ReadDir(filepath.Join(alzlibDir, libraryStoreDirName))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, filepath.Base(entryDir), entries[0].Name())
}

// TestLibraryStoreCustomLibrary checks that a custom library is only stored when its git ref is a
// commit SHA.
func TestLibraryStoreCustomLibrary(t *testing.T) {
	repoDir, commit := newTestLibraryRepo(t, map[string]string{
		"lib/" + testLibraryMetadataFile: testLibraryMetadata,
	})
	runGit(t, repoDir, "branch", "release")

	alzlibDir := useLibraryStore(t)
	downloads := observeDownloads(t, nil)
	ctx := context.Background()

	t.Run("commit", func(t *testing.T) {
		downloads.Store(0)

		getterString := "git::" + fileURL(repoDir) + "//lib?ref=" + commit

		for range 2 {
			libFS, err := NewCustomLibraryReference(getterString).Fetch(ctx, "commit")
			require.NoError(t, err)
			requireLibraryFile(t, libFS, testLibraryMetadataFile)
		}

		assert.Equal(t, int32(1), downloads.Load())
		assert.True(t, libraryStoreEntryComplete(libraryStoreEntry(alzlibDir, getterString), getterString))
		assert.NoDirExists(t, filepath.Join(instanceDir(alzlibDir), "commit"))
	})

	t.Run("branch", func(t *testing.T) {
		downloads.Store(0)

		getterString := "git::" + fileURL(repoDir) + "//lib?ref=release"

		for range 2 {
			libFS, err := NewCustomLibraryReference(getterString).Fetch(ctx, "branch")
			require.NoError(t, err)
			requireLibraryFile(t, libFS, testLibraryMetadataFile)
		}

		assert.Equal(t, int32(2), downloads.Load())
		assert.NoDirExists(t, libraryStoreEntry(alzlibDir, getterString))
		assert.DirExists(t, filepath.Join(instanceDir(alzlibDir), "branch"))
	})

	t.Run("local directory", func(t *testing.T) {
		downloads.Store(0)

		libFS, err := FetchLibraryByGetterString(ctx, "./testdata/simple", "local")
		require.NoError(t, err)
		require.NotNil(t, libFS)
		assert.Equal(t, int32(1), downloads.Load())

		// go-getter links a local directory to the destination, rather than copying it.
		_, err = os.Lstat(filepath.Join(instanceDir(alzlibDir), "local"))
		require.NoError(t, err)
	})
}

// TestLibraryStoreDisabled checks that nothing is stored when the store is disabled.
func TestLibraryStoreDisabled(t *testing.T) {
	newTestAlzLibrary(t)

	alzlibDir := t.TempDir()
	t.Setenv("ALZLIB_DIR", alzlibDir)
	t.Setenv("ALZLIB_LIBRARY_STORE_ENABLED", "")

	downloads := observeDownloads(t, nil)

	for range 2 {
		libFS, err := NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef).Fetch(context.Background(), "dst")
		require.NoError(t, err)
		requireLibraryFile(t, libFS, testLibraryMetadataFile)
	}

	assert.Equal(t, int32(2), downloads.Load())
	assert.NoDirExists(t, filepath.Join(alzlibDir, libraryStoreDirName))
	assert.DirExists(t, filepath.Join(instanceDir(alzlibDir), "dst"))
}

// TestLibraryStoreEnabledByEnvironment checks that the environment variable enables the store.
func TestLibraryStoreEnabledByEnvironment(t *testing.T) {
	newTestAlzLibrary(t)

	alzlibDir := t.TempDir()
	t.Setenv("ALZLIB_DIR", alzlibDir)
	t.Setenv("ALZLIB_LIBRARY_STORE_ENABLED", "true")

	_, err := NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef).Fetch(context.Background(), "dst")
	require.NoError(t, err)

	getterString := alzLibraryMemberGetterString(testAlzMemberPath, testAlzMemberRef)
	assert.True(t, libraryStoreEntryComplete(libraryStoreEntry(alzlibDir, getterString), getterString))
}

// TestLibraryStoreInvalidEntry checks that an entry that is not complete for the requested library is
// left as it is, and that the library is fetched as if the store was disabled.
func TestLibraryStoreInvalidEntry(t *testing.T) {
	newTestAlzLibrary(t)

	getterString := alzLibraryMemberGetterString(testAlzMemberPath, testAlzMemberRef)
	otherMarker, err := json.Marshal(newLibraryStoreMarker("other"))
	require.NoError(t, err)

	cases := []struct {
		name   string
		marker []byte // nil for no marker file
	}{
		{name: "no marker", marker: nil},
		{name: "marker of another library", marker: otherMarker},
		{name: "marker is not json", marker: []byte("{")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alzlibDir := useLibraryStore(t)
			downloads := observeDownloads(t, nil)
			entryDir := libraryStoreEntry(alzlibDir, getterString)
			require.NoError(t, os.MkdirAll(filepath.Join(entryDir, libraryStoreLibDirName), libraryStoreDirPerm))

			markerFile := filepath.Join(entryDir, libraryStoreMarkerFileName)
			if tc.marker != nil {
				require.NoError(t, os.WriteFile(markerFile, tc.marker, libraryStoreFilePerm))
			}

			libFS, err := NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef).Fetch(context.Background(), "dst")
			require.NoError(t, err)
			requireLibraryFile(t, libFS, testLibraryMetadataFile)
			assert.Equal(t, int32(1), downloads.Load())
			assert.DirExists(t, filepath.Join(instanceDir(alzlibDir), "dst"))

			// The entry is unchanged.
			if tc.marker == nil {
				assert.NoFileExists(t, markerFile)
			} else {
				data, err := os.ReadFile(markerFile)
				require.NoError(t, err)
				assert.Equal(t, tc.marker, data)
			}

			entries, err := os.ReadDir(filepath.Join(entryDir, libraryStoreLibDirName))
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}
}

// TestLibraryStoreConcurrentFetches checks that goroutines fetching the same library download it once.
func TestLibraryStoreConcurrentFetches(t *testing.T) {
	newTestAlzLibrary(t)
	useLibraryStore(t)
	downloads := observeDownloads(t, nil)

	var wg sync.WaitGroup

	errs := make([]error, testLibraryStoreGoroutines)
	fss := make([]fs.FS, testLibraryStoreGoroutines)

	for i := range testLibraryStoreGoroutines {
		wg.Go(func() {
			ref := NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef)
			fss[i], errs[i] = ref.Fetch(context.Background(), "dst")
		})
	}

	wg.Wait()

	for i := range testLibraryStoreGoroutines {
		require.NoError(t, errs[i])
		requireLibraryFile(t, fss[i], testLibraryMetadataFile)
	}

	assert.Equal(t, int32(1), downloads.Load())
}

// TestLibraryStoreEntryAddedByAnotherProcess checks that the entry of another process is used when that
// process adds it first.
func TestLibraryStoreEntryAddedByAnotherProcess(t *testing.T) {
	newTestAlzLibrary(t)
	alzlibDir := useLibraryStore(t)

	const otherFile = "other.json"

	getterString := alzLibraryMemberGetterString(testAlzMemberPath, testAlzMemberRef)
	entryDir := libraryStoreEntry(alzlibDir, getterString)

	observeDownloads(t, func(_, _ string, err error) error {
		// The other process adds the entry while this one downloads the library.
		otherLibDir := filepath.Join(entryDir, libraryStoreLibDirName)
		require.NoError(t, os.MkdirAll(otherLibDir, libraryStoreDirPerm))
		require.NoError(t, os.WriteFile(filepath.Join(otherLibDir, otherFile), []byte("{}"), libraryStoreFilePerm))

		marker, merr := json.Marshal(newLibraryStoreMarker(getterString))
		require.NoError(t, merr)
		require.NoError(t, os.WriteFile(filepath.Join(entryDir, libraryStoreMarkerFileName), marker, libraryStoreFilePerm))

		return err
	})

	libFS, err := NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef).Fetch(context.Background(), "dst")
	require.NoError(t, err)
	requireLibraryFile(t, libFS, otherFile)

	// The library that this process downloaded has been removed.
	entries, err := os.ReadDir(filepath.Join(alzlibDir, libraryStoreDirName))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, filepath.Base(entryDir), entries[0].Name())
}

// TestLibraryStoreRenameWhileFileIsOpen checks that an entry is added while another process has one of
// its files open for a short time. On Windows, this makes the rename fail until the file is closed.
func TestLibraryStoreRenameWhileFileIsOpen(t *testing.T) {
	newTestAlzLibrary(t)
	useLibraryStore(t)

	observeDownloads(t, func(_, dst string, err error) error {
		if err != nil {
			return err
		}

		f, err := os.Open(filepath.Join(dst, testLibraryMetadataFile))
		require.NoError(t, err)

		time.AfterFunc(testOpenFileDuration, func() { _ = f.Close() })

		return nil
	})

	libFS, err := NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef).Fetch(context.Background(), "dst")
	require.NoError(t, err)
	requireLibraryFile(t, libFS, testLibraryMetadataFile)
}

// TestLibraryStoreConcurrentProcesses checks that processes fetching the same library into the same
// store at the same time all get the complete library, and leave one entry.
func TestLibraryStoreConcurrentProcesses(t *testing.T) {
	newTestAlzLibrary(t)
	alzlibDir := useLibraryStore(t)

	cmds := make([]*exec.Cmd, testLibraryStoreProcesses)
	outputs := make([]*bytes.Buffer, testLibraryStoreProcesses)

	for i := range cmds {
		outputs[i] = new(bytes.Buffer)
		cmds[i] = exec.Command(os.Args[0], "-test.run=^TestLibraryStoreHelperProcess$", "-test.count=1")

		cmds[i].Env = append(os.Environ(), testLibraryStoreHelperEnv+"=1", "ALZLIB_LIBRARY_STORE_ENABLED=true")
		cmds[i].Stdout = outputs[i]
		cmds[i].Stderr = outputs[i]
	}

	for _, cmd := range cmds {
		require.NoError(t, cmd.Start())
	}

	for i, cmd := range cmds {
		require.NoError(t, cmd.Wait(), "process %d: %s", i, outputs[i])
	}

	getterString := alzLibraryMemberGetterString(testAlzMemberPath, testAlzMemberRef)
	entryDir := libraryStoreEntry(alzlibDir, getterString)
	assert.True(t, libraryStoreEntryComplete(entryDir, getterString))

	entries, err := os.ReadDir(filepath.Join(alzlibDir, libraryStoreDirName))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, filepath.Base(entryDir), entries[0].Name())
}

// TestLibraryStoreHelperProcess fetches the test ALZ Library member in a process started by
// TestLibraryStoreConcurrentProcesses.
func TestLibraryStoreHelperProcess(t *testing.T) {
	if os.Getenv(testLibraryStoreHelperEnv) != "1" {
		t.Skip("run by TestLibraryStoreConcurrentProcesses")
	}

	libFS, err := NewAlzLibraryReference(testAlzMemberPath, testAlzMemberRef).Fetch(context.Background(), "dst")
	require.NoError(t, err)
	requireLibraryFile(t, libFS, testLibraryMetadataFile)
}
