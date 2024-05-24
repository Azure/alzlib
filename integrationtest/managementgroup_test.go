// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
)

func TestAddManagementGroup(t *testing.T) {
	t.Parallel()
	// create a new deployment type.
	az := alzlib.NewAlzLib(nil)

	// create a new archetype
	arch := &alzlib.Archetype{
		PolicyDefinitions:    mapset.NewSet[string](),
		PolicySetDefinitions: mapset.NewSet[string](),
		PolicyAssignments:    mapset.NewSet[string](),
		RoleDefinitions:      mapset.NewSet[string](),
	}

	// test adding a new management group with no parent.
	req := deployment.ManagementGroupAddRequest{
		Id:               "mg1",
		DisplayName:      "mg1",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
		Location:         "uksouth",
	}
	depl := deployment.NewHierarchy(az)

	mg, err := depl.AddManagementGroup(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, slices.Equal(depl.ListManagementGroups(), []string{"mg1"}))
	assert.Len(t, mg.Children(), 0)
	assert.Equal(t, "mg1", mg.DisplayName())
	assert.Nil(t, mg.Parent())
	assert.True(t, mg.ParentIsExternal())
	assert.Equal(t, fmt.Sprintf(deployment.ManagementGroupIdFmt, "mg1"), mg.ResourceId())

	req = deployment.ManagementGroupAddRequest{
		Id:               "mg2",
		DisplayName:      "mg2",
		ParentId:         "mg1",
		ParentIsExternal: false,
		Archetype:        arch,
		Location:         "eastus2",
	}
	// test adding a new management group with a parent.
	mg, err = depl.AddManagementGroup(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, depl.ListManagementGroups(), 2)
	assert.Contains(t, depl.ListManagementGroups(), "mg2")
	assert.Equal(t, "mg2", mg.Name())
	assert.Equal(t, "mg2", mg.DisplayName())
	assert.NotNil(t, mg.Parent())
	assert.Equal(t, "mg1", mg.Parent().Name())
	assert.Len(t, mg.Parent().Children(), 1)
	assert.Equal(t, "mg2", mg.Parent().Children()[0].Name())
	assert.False(t, mg.ParentIsExternal())
	assert.Equal(t, mg.Parent(), mg.Parent().Children()[0].Parent())

	req = deployment.ManagementGroupAddRequest{
		Id:               "mg3",
		DisplayName:      "mg3",
		ParentId:         "mg4",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	// test adding a new management group with a non-existent parent.
	_, err = depl.AddManagementGroup(context.Background(), req)
	assert.Error(t, err)

	req = deployment.ManagementGroupAddRequest{
		Id:               "mg4",
		DisplayName:      "mg4",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	// test adding a new management group with multiple root management groups.
	_, err = depl.AddManagementGroup(context.Background(), req)
	assert.Error(t, err)

	req = deployment.ManagementGroupAddRequest{
		Id:               "mg1",
		DisplayName:      "mg1",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	// test adding a new management group with an existing name.
	_, err = depl.AddManagementGroup(context.Background(), req)
	assert.Error(t, err)
}
