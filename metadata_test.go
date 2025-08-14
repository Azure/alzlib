// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFetchLibrariesWithDependencies tests fetching libraries with dependencies and they they are
// fetched in the right
// order.
func TestFetchLibrariesWithDependencies(t *testing.T) {
	ctx := context.Background()

	require.NoError(t, os.RemoveAll(".alzlib"))

	defer os.RemoveAll(".alzlib") // nolint: errcheck

	expcted := []string{
		"testdata/dependent-libs/lib2",
		"testdata/dependent-libs/lib1",
		"testdata/dependent-libs/libB",
		"testdata/dependent-libs/libA",
	}
	lib1 := NewCustomLibraryReference("testdata/dependent-libs/lib1")
	libA := NewCustomLibraryReference("testdata/dependent-libs/libA")
	libs := LibraryReferences{lib1, libA}
	libs, err := libs.FetchWithDependencies(ctx)
	require.NoError(t, err)
	require.Len(t, libs, 4)

	result := make([]string, 4)
	for i, lib := range libs {
		result[i] = lib.String()
	}

	assert.ElementsMatch(t, expcted, result)
}

// TestFetchLibrariesWithCommonDependency checks that a libraries having a common dependency is
// fetched only once.
func TestFetchLibrariesWithCommonDependency(t *testing.T) {
	ctx := context.Background()

	require.NoError(t, os.RemoveAll(".alzlib"))

	defer os.RemoveAll(".alzlib") // nolint: errcheck

	expcted := []string{
		"testdata/dependent-libs/lib2",
		"testdata/dependent-libs/lib1",
		"testdata/dependent-libs/lib3",
	}
	lib1 := NewCustomLibraryReference("testdata/dependent-libs/lib1")
	libA := NewCustomLibraryReference("testdata/dependent-libs/lib3")
	libs := LibraryReferences{lib1, libA}
	libs, err := libs.FetchWithDependencies(ctx)
	require.NoError(t, err)
	require.Len(t, libs, 3)

	result := make([]string, 3)
	for i, lib := range libs {
		result[i] = lib.String()
	}

	assert.ElementsMatch(t, expcted, result)
}
