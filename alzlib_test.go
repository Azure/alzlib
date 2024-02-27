// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
)

// TestInitMultiLib tests that we can initialize the library with multiple urlss.
func TestInitMultiLib(t *testing.T) {
	az := NewAlzLib()
	az.Options.AllowOverwrite = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remoteLib, err := getRemoteLib(ctx)
	assert.NoError(t, err)
	dirfs := os.DirFS("./testdata/simple")
	err = az.Init(ctx, remoteLib, dirfs)
	assert.NoError(t, err)
	assert.Equal(t, 11, len(az.archetypes))
	// Test root archetype has been overridden
	assert.Equal(t, 1, az.archetypes["root"].PolicyDefinitions.Cardinality())
}

// Test_NewAlzLib_noDir tests the creation of a new AlzLib when supplied with a path
// that does not exist.
// The error details are checked for the expected error message.
func TestNewAlzLibWithNoDir(t *testing.T) {
	az := NewAlzLib()
	path := filepath.Join("testdata", "doesnotexist")
	dir := os.DirFS(path)
	err := az.Init(context.Background(), dir)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestAddManagementGroup(t *testing.T) {
	t.Parallel()
	// create a new deployment type.
	wkvs := &WellKnownPolicyValues{
		DefaultLocation: to.Ptr("eastus"),
	}
	az := NewAlzLib()

	// create a new archetype
	arch := &Archetype{
		PolicyDefinitions:    mapset.NewSet[string](),
		PolicySetDefinitions: mapset.NewSet[string](),
		PolicyAssignments:    mapset.NewSet[string](),
		RoleDefinitions:      mapset.NewSet[string](),
	}
	arch.wellKnownPolicyValues = wkvs

	// test adding a new management group with no parent.
	req := AlzManagementGroupAddRequest{
		Id:               "mg1",
		DisplayName:      "mg1",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	err := az.AddManagementGroupToDeployment(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, az.Deployment.mgs, 1)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Equal(t, "mg1", az.Deployment.mgs["mg1"].name)
	assert.Equal(t, "mg1", az.Deployment.mgs["mg1"].displayName)
	assert.Nil(t, az.Deployment.mgs["mg1"].parent)
	assert.Equal(t, az.Deployment.mgs["mg1"].children.Cardinality(), 0)
	assert.True(t, az.Deployment.mgs["mg1"].ParentIsExternal())
	assert.Equal(t, fmt.Sprintf(managementGroupIdFmt, "mg1"), az.Deployment.mgs["mg1"].GetResourceId())

	req = AlzManagementGroupAddRequest{
		Id:               "mg2",
		DisplayName:      "mg2",
		ParentId:         "mg1",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	// test adding a new management group with a parent.
	err = az.AddManagementGroupToDeployment(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg2")
	assert.Equal(t, "mg2", az.Deployment.mgs["mg2"].name)
	assert.Equal(t, "mg2", az.Deployment.mgs["mg2"].displayName)
	assert.NotNil(t, az.Deployment.mgs["mg2"].parent)
	assert.Equal(t, "mg1", az.Deployment.mgs["mg2"].parent.name)
	assert.Equal(t, az.Deployment.mgs["mg1"].children.Cardinality(), 1)
	assert.Equal(t, "mg2", az.Deployment.mgs["mg1"].children.ToSlice()[0].name)
	assert.False(t, az.Deployment.mgs["mg2"].ParentIsExternal())
	assert.Equal(t, az.Deployment.mgs["mg1"], az.Deployment.mgs["mg2"].GetParentMg())

	req = AlzManagementGroupAddRequest{
		Id:               "mg3",
		DisplayName:      "mg3",
		ParentId:         "mg4",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	// test adding a new management group with a non-existent parent.
	err = az.AddManagementGroupToDeployment(context.Background(), req)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
	assert.NotContains(t, az.Deployment.mgs, "mg3")

	req = AlzManagementGroupAddRequest{
		Id:               "mg4",
		DisplayName:      "mg4",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	// test adding a new management group with multiple root management groups.
	err = az.AddManagementGroupToDeployment(context.Background(), req)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
	assert.NotContains(t, az.Deployment.mgs, "mg4")

	req = AlzManagementGroupAddRequest{
		Id:               "mg1",
		DisplayName:      "mg1",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	// test adding a new management group with an existing name.
	err = az.AddManagementGroupToDeployment(context.Background(), req)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
}

// Test_NewAlzLibDuplicateArchetypeDefinition tests the creation of a new AlzLib from a invalid source directory.
func TestNewAlzLibDuplicateArchetypeDefinition(t *testing.T) {
	az := NewAlzLib()
	dir := os.DirFS("./testdata/badlib-duplicatearchetypedef")
	err := az.Init(context.Background(), dir)
	assert.ErrorContains(t, err, "archetype with name duplicate already exists")
}

func TestGetBuiltInPolicy(t *testing.T) {
	az := NewAlzLib()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	err = az.getBuiltInPolicies(context.Background(), []string{"8154e3b3-cc52-40be-9407-7756581d71f6"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.policyDefinitions))
	assert.Equal(t, "Microsoft Managed Control 1614 - Developer Security Architecture And Design", *az.policyDefinitions["8154e3b3-cc52-40be-9407-7756581d71f6"].Properties.DisplayName)
}

func TestGetBuiltInPolicySet(t *testing.T) {
	az := NewAlzLib()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	err = az.getBuiltInPolicySets(context.Background(), []string{"7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.policySetDefinitions))
	assert.Equal(t, "Evaluate Private Link Usage Across All Supported Azure Resources", *az.policySetDefinitions["7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"].Properties.DisplayName)
	assert.Equal(t, 30, len(az.policyDefinitions))
}
