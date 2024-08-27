// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchLibraryByGetterString(t *testing.T) {
	ctx := context.Background()
	dstDir := "test-library"
	defer os.RemoveAll(filepath.Join(".alzlib", dstDir))

	fs, err := FetchLibraryByGetterString(ctx, "./testdata/simple", dstDir)
	assert.NoError(t, err)
	assert.NotNil(t, fs)
}

func TestFetchLibraryWithDependencies(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, os.RemoveAll(".alzlib"))
	defer os.RemoveAll(".alzlib") // nolint: errcheck

	libs, err := FetchLibraryWithDependencies(ctx, 0, NewCustomLibraryReference("./testdata/dependent-libs/lib1"), make(LibraryReferences, 0, 2))
	assert.NoError(t, err)
	assert.Len(t, libs, 2)
}

func TestFetchLibraryWithDependencies_MissingCustomDependency(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, os.RemoveAll(".alzlib"))
	defer os.RemoveAll(".alzlib") // nolint: errcheck

	_, err := FetchLibraryWithDependencies(ctx, 0, NewCustomLibraryReference("./testdata/dependent-libs/missing-dep-custom"), make(LibraryReferences, 0, 2))
	assert.ErrorContains(t, err, "could not fetch library member")
}

func TestFetchLibraryWithDependencies_MissingLibraryDependency(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, os.RemoveAll(".alzlib"))
	defer os.RemoveAll(".alzlib") // nolint: errcheck

	_, err := FetchLibraryWithDependencies(ctx, 0, NewCustomLibraryReference("./testdata/dependent-libs/missing-dep-library"), make(LibraryReferences, 0, 2))
	assert.ErrorContains(t, err, "could not fetch library member")
}
