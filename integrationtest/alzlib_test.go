// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
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
	remoteLib := alzlib.NewAlzLibraryReference(alzLibraryMember, alzLibraryTag)
	_, err := remoteLib.Fetch(ctx, "alz")
	require.NoError(t, err)
	localLib := alzlib.NewCustomLibraryReference("../testdata/simple")
	_, err = localLib.Fetch(ctx, "simple")
	require.NoError(t, err)
	err = az.Init(ctx, remoteLib, localLib)
	require.NoError(t, err)
	assert.Equal(t, 13, len(az.Archetypes()))
	// Test root archetype has been overridden
	arch := az.Archetype("root")
	assert.Equal(t, 158, arch.PolicyDefinitions.Cardinality())
	arch = az.Archetype("simpleoverride")
	assert.Equal(t, 1, arch.PolicyDefinitions.Cardinality())
	assert.Equal(t, 1, arch.PolicyAssignments.Cardinality())
}

func TestInitSimpleExistingMg(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	lib := alzlib.NewCustomLibraryReference("./testdata/simple-existingmg")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, az.Init(ctx, lib))
	assert.Equal(t, []string{"empty", "simple"}, az.Archetypes())
	assert.Equal(t, []string{"test-policy-definition"}, az.PolicyDefinitions())
	assert.Equal(t, []string{"test-policy-set-definition"}, az.PolicySetDefinitions())
	assert.Equal(t, []string{"test-role-definition"}, az.RoleDefinitions())
	assert.Equal(t, []string{"test-policy-assignment"}, az.PolicyAssignments())
	assert.Equal(t, []string{"test"}, az.PolicyDefaultValues())
	h := deployment.NewHierarchy(az)
	err := h.FromArchitecture(ctx, "simple", "00000000-0000-0000-0000-000000000000", "testlocation")
	require.NoError(t, err)
	mg := h.ManagementGroup("simple")
	assert.False(t, mg.Exists())
}
