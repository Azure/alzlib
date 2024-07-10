// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"os"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	alzLibraryTag    = "2024.07.02"
	alzLibraryMember = "platform/alz"
)

func TestNewAlzLibOptionsError(t *testing.T) {
	az := new(alzlib.AlzLib)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	assert.ErrorContains(t, az.Init(ctx), "parallelism")
	az.Options = new(alzlib.AlzLibOptions)
	assert.ErrorContains(t, az.Init(ctx), "parallelism")
}

// TestInitMultiLib tests that we can initialize the library with multiple urls.
func TestInitMultiLib(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	az.Options.AllowOverwrite = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remoteLib, err := alzlib.FetchAzureLandingZonesLibraryMember(ctx, alzLibraryMember, alzLibraryTag, "alz")
	require.NoError(t, err)
	dirfs := os.DirFS("../testdata/simple")
	err = az.Init(ctx, remoteLib, dirfs)
	require.NoError(t, err)
	assert.Equal(t, 13, len(az.Archetypes()))
	// Test root archetype has been overridden
	arch, _ := az.Archetype("root")
	assert.Equal(t, 158, arch.PolicyDefinitions.Cardinality())
	arch, err = az.Archetype("simpleoverride")
	require.NoError(t, err)
	assert.Equal(t, 1, arch.PolicyDefinitions.Cardinality())
	assert.Equal(t, 1, arch.PolicyAssignments.Cardinality())
}
