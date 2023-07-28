// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	sets "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
)

// ExampleAlzLib_Init demonstrates the creation of a new AlzLib based a sample directory.
func ExampleAlzLib_Init() {
	az := NewAlzLib()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirfs := os.DirFS("./testdata/simple")
	err := az.Init(ctx, dirfs)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Archetype count: %d\n", len(az.archetypes))
	// Output:
	// Archetype count: 2
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
		DefaultLocation: "eastus",
	}
	az := NewAlzLib()

	// create a new archetype
	arch := &Archetype{
		PolicyDefinitions:    sets.NewSet[string](),
		PolicySetDefinitions: sets.NewSet[string](),
		PolicyAssignments:    sets.NewSet[string](),
		RoleDefinitions:      sets.NewSet[string](),
	}
	arch.wellKnownPolicyValues = wkvs

	// test adding a new management group with no parent.
	err := az.AddManagementGroupToDeployment("mg1", "mg1", "external", true, arch)
	assert.NoError(t, err)
	assert.Len(t, az.Deployment.mgs, 1)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Equal(t, "mg1", az.Deployment.mgs["mg1"].name)
	assert.Equal(t, "mg1", az.Deployment.mgs["mg1"].displayName)
	assert.Nil(t, az.Deployment.mgs["mg1"].parent)
	assert.Equal(t, az.Deployment.mgs["mg1"].children.Cardinality(), 0)
	assert.True(t, az.Deployment.mgs["mg1"].ParentIsExternal())
	assert.Equal(t, fmt.Sprintf(managementGroupIdFmt, "mg1"), az.Deployment.mgs["mg1"].GetResourceId())

	// test adding a new management group with a parent.
	err = az.AddManagementGroupToDeployment("mg2", "mg2", "mg1", false, arch)
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

	// test adding a new management group with a non-existent parent.
	err = az.AddManagementGroupToDeployment("mg3", "mg3", "mg4", false, arch)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
	assert.NotContains(t, az.Deployment.mgs, "mg3")

	// test adding a new management group with multiple root management groups.
	err = az.AddManagementGroupToDeployment("mg4", "mg4", "external", true, arch)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
	assert.NotContains(t, az.Deployment.mgs, "mg4")

	// test adding a new management group with an existing name.
	err = az.AddManagementGroupToDeployment("mg1", "mg1", "external", true, arch)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
}

// Test_NewAlzLibDuplicateArchetypeDefinition tests the creation of a new AlzLib from a invalid source directory.
func Test_NewAlzLibDuplicateArchetypeDefinition(t *testing.T) {
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
	err = az.GetBuiltInPolicies(context.Background(), []string{"8154e3b3-cc52-40be-9407-7756581d71f6"})
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
	err = az.GetBuiltInPolicySets(context.Background(), []string{"7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.policySetDefinitions))
	assert.Equal(t, "Evaluate Private Link Usage Across All Supported Azure Resources", *az.policySetDefinitions["7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"].Properties.DisplayName)
	assert.Equal(t, 30, len(az.policyDefinitions))
}
