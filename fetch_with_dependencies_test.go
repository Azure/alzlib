// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/alzlib/internal/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRandomGraphs          = 40
	testRandomGraphMaxSize    = 8
	testIndependentLibraries  = 10
	testConcurrencyWaitPeriod = 5 * time.Second
	testDownloadDuration      = 20 * time.Millisecond
	testErrorRepetitions      = 5
)

// sequentialFetchLibraryWithDependencies is the implementation of FetchWithDependencies from before
// libraries were fetched concurrently. The tests check that the libraries are returned in the same
// order.
func sequentialFetchLibraryWithDependencies(
	ctx context.Context,
	processed map[string]bool,
	lib LibraryReference,
	result *LibraryReferences,
) error {
	if processed[lib.String()] {
		return nil
	}

	f, err := lib.Fetch(ctx, hash(lib))
	if err != nil {
		return err
	}

	libmeta, err := processor.NewClient(f).Metadata()
	if err != nil {
		return err
	}

	for _, dep := range NewMetadata(libmeta, lib).Dependencies() {
		if err := sequentialFetchLibraryWithDependencies(ctx, processed, dep, result); err != nil {
			return err
		}
	}

	*result = append(*result, lib)
	processed[lib.String()] = true

	return nil
}

// writeTestLibrary writes a library to dir, with dependencies on the libraries in the directories deps.
func writeTestLibrary(t *testing.T, dir string, deps ...string) {
	t.Helper()

	dependencies := make([]processor.LibMetadataDependency, len(deps))
	for i, dep := range deps {
		dependencies[i] = processor.LibMetadataDependency{CustomURL: filepath.ToSlash(dep)}
	}

	data, err := json.Marshal(processor.LibMetadata{
		Name:         filepath.Base(dir),
		DisplayName:  filepath.Base(dir),
		Description:  "test library",
		Dependencies: dependencies,
	})
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, libraryStoreDirPerm))
	require.NoError(t, os.WriteFile(filepath.Join(dir, testLibraryMetadataFile), data, libraryStoreFilePerm))
}

// libraryNames returns the String() of the libraries.
func libraryNames(libs LibraryReferences) []string {
	names := make([]string, len(libs))
	for i, lib := range libs {
		names[i] = lib.String()
	}

	return names
}

// TestFetchWithDependenciesOrder checks that libraries are returned in the same order as by the
// sequential implementation, for random dependency graphs with shared and diamond dependencies.
func TestFetchWithDependenciesOrder(t *testing.T) {
	t.Setenv("ALZLIB_DIR", t.TempDir())

	ctx := context.Background()

	for seed := range uint64(testRandomGraphs) {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			rnd := rand.New(rand.NewPCG(seed, seed))
			libDir := t.TempDir()
			size := 1 + rnd.IntN(testRandomGraphMaxSize)

			dirs := make([]string, size)
			for i := range dirs {
				dirs[i] = filepath.Join(libDir, fmt.Sprintf("lib%d", i))
			}

			// A library only depends on libraries with a lower index, so that there is no cycle.
			for i, dir := range dirs {
				var deps []string

				for _, j := range rnd.Perm(i) {
					if rnd.IntN(2) == 0 {
						deps = append(deps, dirs[j])
					}
				}

				writeTestLibrary(t, dir, deps...)
			}

			top := rnd.Perm(size)[:1+rnd.IntN(size)]
			newRefs := func() LibraryReferences {
				refs := make(LibraryReferences, len(top))
				for i, j := range top {
					refs[i] = NewCustomLibraryReference(filepath.ToSlash(dirs[j]))
				}

				return refs
			}

			var want LibraryReferences

			processed := make(map[string]bool)
			for _, lib := range newRefs() {
				require.NoError(t, sequentialFetchLibraryWithDependencies(ctx, processed, lib, &want))
			}

			got, err := newRefs().FetchWithDependencies(ctx)
			require.NoError(t, err)
			assert.Equal(t, libraryNames(want), libraryNames(got))

			for _, lib := range got {
				assert.NotNil(t, lib.FS(), lib.String())
			}
		})
	}
}

// TestFetchWithDependenciesConcurrency checks that independent libraries are fetched concurrently, at
// most maxConcurrentLibraryFetches at a time.
func TestFetchWithDependenciesConcurrency(t *testing.T) {
	t.Setenv("ALZLIB_DIR", t.TempDir())

	libDir := t.TempDir()
	refs := make(LibraryReferences, testIndependentLibraries)

	for i := range refs {
		dir := filepath.Join(libDir, fmt.Sprintf("lib%d", i))
		writeTestLibrary(t, dir)
		refs[i] = NewCustomLibraryReference(filepath.ToSlash(dir))
	}

	var (
		inFlight, maxInFlight atomic.Int32
		concurrent            = make(chan struct{})
		closeConcurrent       sync.Once
	)

	download := downloadLibrary
	downloadLibrary = func(ctx context.Context, getterString, dst string) error {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)

		for current := maxInFlight.Load(); n > current && !maxInFlight.CompareAndSwap(current, n); {
			current = maxInFlight.Load()
		}

		// Wait until two downloads overlap, which never happens if the libraries are fetched one by one.
		if n > 1 {
			closeConcurrent.Do(func() { close(concurrent) })
		}

		select {
		case <-concurrent:
		case <-time.After(testConcurrencyWaitPeriod):
		}

		time.Sleep(testDownloadDuration)

		return download(ctx, getterString, dst)
	}

	t.Cleanup(func() { downloadLibrary = download })

	got, err := refs.FetchWithDependencies(context.Background())
	require.NoError(t, err)
	assert.Equal(t, libraryNames(refs), libraryNames(got))
	assert.Greater(t, maxInFlight.Load(), int32(1))
	assert.LessOrEqual(t, maxInFlight.Load(), int32(maxConcurrentLibraryFetches))
}

// TestFetchWithDependenciesReusesPrefetchedLibrary checks that a library is fetched once when it is
// referenced more than once, and that the first reference in the depth-first walk is returned, as by
// the sequential implementation.
func TestFetchWithDependenciesReusesPrefetchedLibrary(t *testing.T) {
	t.Setenv("ALZLIB_DIR", t.TempDir())

	libDir := t.TempDir()
	shared := filepath.Join(libDir, "shared")
	dependent := filepath.Join(libDir, "dependent")

	writeTestLibrary(t, shared)
	writeTestLibrary(t, dependent, shared)

	downloads := observeDownloads(t, nil)
	sharedRef := NewCustomLibraryReference(filepath.ToSlash(shared))
	refs := LibraryReferences{NewCustomLibraryReference(filepath.ToSlash(dependent)), sharedRef}

	got, err := refs.FetchWithDependencies(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.ToSlash(shared), filepath.ToSlash(dependent)}, libraryNames(got))
	assert.Equal(t, int32(2), downloads.Load())

	// The shared library is returned as the dependency of the dependent library, not as sharedRef.
	assert.NotSame(t, sharedRef, got[0])
	assert.NotNil(t, got[0].FS())
}

// TestFetchWithDependenciesCircularDependency checks that a circular dependency is an error.
func TestFetchWithDependenciesCircularDependency(t *testing.T) {
	t.Setenv("ALZLIB_DIR", t.TempDir())

	libDir := t.TempDir()
	libA := filepath.Join(libDir, "libA")
	libB := filepath.Join(libDir, "libB")

	writeTestLibrary(t, libA, libB)
	writeTestLibrary(t, libB, libA)

	_, err := NewCustomLibraryReference(filepath.ToSlash(libA)).FetchWithDependencies(context.Background())
	require.ErrorContains(t, err, "circular dependency on library "+filepath.ToSlash(libA))
}

// TestFetchWithDependenciesFirstError checks that the error of the first library that fails, in the
// depth-first walk, is returned, whichever fetch fails first.
func TestFetchWithDependenciesFirstError(t *testing.T) {
	t.Setenv("ALZLIB_DIR", t.TempDir())

	libDir := t.TempDir()
	missing1 := filepath.ToSlash(filepath.Join(libDir, "missing1"))
	missing2 := filepath.ToSlash(filepath.Join(libDir, "missing2"))

	for range testErrorRepetitions {
		refs := LibraryReferences{NewCustomLibraryReference(missing1), NewCustomLibraryReference(missing2)}
		libs, err := refs.FetchWithDependencies(context.Background())
		require.ErrorContains(t, err, "error fetching library "+missing1+":")
		assert.NotContains(t, err.Error(), missing2)
		assert.Nil(t, libs)
	}
}
