// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
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

	require.ErrorContains(t, az.Init(ctx), "parallelism")
	az.Options = new(alzlib.Options)
	require.ErrorContains(t, az.Init(ctx), "parallelism")
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
	assert.Len(t, az.Archetypes(), 13)
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
	assert.True(t, mg.Exists())
}

func TestInitMultipleRoleDefinitions(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	lib := alzlib.NewCustomLibraryReference("./testdata/multipleroledefinitions")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, az.Init(ctx, lib))
	h := deployment.NewHierarchy(az)
	err := h.FromArchitecture(ctx, "test", "00000000-0000-0000-0000-000000000000", "testlocation")
	require.NoError(t, err)

	mg1 := h.ManagementGroup("test1")
	mg2 := h.ManagementGroup("test2")
	assert.NotEqual(
		t,
		mg1.RoleDefinitionsMap()["test-role-definition"].Name,
		mg2.RoleDefinitionsMap()["test-role-definition"].Name,
	)
}

func TestPolicyRoleAssignmentsWithComplexFunctions(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	lib := alzlib.NewCustomLibraryReference("./testdata/policydefaultscomplexfunc")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	require.NoError(t, err)
	az.AddPolicyClient(cf)
	require.NoError(t, az.Init(ctx, lib))
	h := deployment.NewHierarchy(az)
	require.NoError(
		t,
		h.AddDefaultPolicyAssignmentValue(
			ctx,
			"private_dns_zone_subscription_id",
			&armpolicy.ParameterValuesValue{Value: "00000000-0000-0000-0000-000000000000"},
		),
	)
	require.NoError(
		t,
		h.AddDefaultPolicyAssignmentValue(
			ctx,
			"private_dns_zone_resource_group_name",
			&armpolicy.ParameterValuesValue{Value: "test"},
		),
	)
	require.NoError(
		t,
		h.AddDefaultPolicyAssignmentValue(
			ctx,
			"private_dns_zone_region",
			&armpolicy.ParameterValuesValue{Value: "testlocation"},
		),
	)
	require.NoError(t, h.FromArchitecture(ctx, "test", "private_dns_zone_region", "testlocation"))
	_, err = h.PolicyRoleAssignments(ctx)

	var roleAssignmentErrors *deployment.PolicyRoleAssignmentErrors

	require.NoError(t, err, roleAssignmentErrors)
}

func TestInvalidParent(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	lib := alzlib.NewCustomLibraryReference("./testdata/invalidparent")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	require.NoError(t, err)
	az.AddPolicyClient(cf)
	require.ErrorContains(t, az.Init(ctx, lib), "has invalid parent")
}

func TestExistsChildOnNotExistParent(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	lib := alzlib.NewCustomLibraryReference("./testdata/existingchildwithnotexistingparent")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	require.NoError(t, err)
	az.AddPolicyClient(cf)
	require.ErrorContains(
		t,
		az.Init(ctx, lib),
		"which is configured as existing but the parent management group",
	)
}
