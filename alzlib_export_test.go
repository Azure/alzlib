// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib_test

import (
	"context"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/stretchr/testify/require"
)

func TestInitWithLocalOverrideOfAlzLibrary(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	ctx := context.Background()
	lib1 := alzlib.NewAlzLibraryReference("platform/alz", "2024.07.01")
	_, err := lib1.Fetch(ctx, "0")
	require.NoError(t, err)

	lib2 := alzlib.NewCustomLibraryReference("./testdata/overrideAlzLibrary")
	_, err = lib2.Fetch(ctx, "1")
	require.NoError(t, err)
	err = az.Init(ctx, lib1, lib2)
	require.NoError(t, err)
}
