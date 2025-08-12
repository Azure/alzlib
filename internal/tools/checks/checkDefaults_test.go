// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package checks

import (
	"context"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDefaultsGood(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	ctx := context.Background()
	lib := alzlib.NewCustomLibraryReference("testdata/defaultsgood")
	_, err := lib.Fetch(ctx, "0")
	require.NoError(t, err)
	require.NoError(t, az.Init(ctx, lib))
	require.NoError(t, checkDefaults(az))
}

func TestCheckDefaultsAssignmentNotPresent(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	ctx := context.Background()
	lib := alzlib.NewCustomLibraryReference("testdata/defaultsassignmentnotpresent")
	_, err := lib.Fetch(ctx, "0")
	require.NoError(t, err)
	require.NoError(t, az.Init(ctx, lib))
	assert.ErrorContains(
		t,
		checkDefaults(az),
		"policy assignment `not_present`, referenced by default `test` is not found in the library",
	)
}

func TestCheckDefaultsParameterNotPresent(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	ctx := context.Background()
	lib := alzlib.NewCustomLibraryReference("testdata/defaultsparameternotpresent")
	_, err := lib.Fetch(ctx, "0")
	require.NoError(t, err)
	require.NoError(t, az.Init(ctx, lib))
	assert.ErrorContains(
		t,
		checkDefaults(az),
		"policy assignment `test-policy-assignment`, referenced by default `test` has a parameter `not_present` that is not present in the referenced definition",
	)
}
