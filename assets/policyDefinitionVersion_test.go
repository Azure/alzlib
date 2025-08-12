// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package assets

import (
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
)

func TestVersionNormalizedRoleDefinitionResourceIds(t *testing.T) {
	pd := &PolicyDefinitionVersion{
		DefinitionVersion: armpolicy.DefinitionVersion{
			Properties: &armpolicy.DefinitionVersionProperties{
				PolicyRule: map[string]any{
					"Then": map[string]any{
						"Details": map[string]any{
							"RoleDefinitionIds": []string{
								"/providers/Microsoft.Authorization/roleDefinitions/role1",
								"/providers/Microsoft.Authorization/roleDefinitions/role2",
							},
						},
					},
				},
			},
		},
	}

	expected := []string{
		"/providers/Microsoft.Authorization/roleDefinitions/role1",
		"/providers/Microsoft.Authorization/roleDefinitions/role2",
	}

	ids, err := pd.NormalizedRoleDefinitionResourceIDs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ids) != len(expected) {
		t.Fatalf("expected %d role definition ids, got %d", len(expected), len(ids))
	}

	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("expected role definition id %s, got %s", expected[i], id)
		}
	}
}

func TestVersionSetAssignPermissionsOnParameter(t *testing.T) {
	pd := &PolicyDefinitionVersion{
		DefinitionVersion: armpolicy.DefinitionVersion{
			Properties: &armpolicy.DefinitionVersionProperties{
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
					"test": {
						Metadata: &armpolicy.ParameterDefinitionsValueMetadata{},
					},
				},
			},
		},
	}
	pd.SetAssignPermissionsOnParameter("test")
	assert.True(t, *pd.Properties.Parameters["test"].Metadata.AssignPermissions)
}

func TestVersionUnsetAssignPermissionsOnParameter(t *testing.T) {
	pd := &PolicyDefinitionVersion{
		DefinitionVersion: armpolicy.DefinitionVersion{
			Properties: &armpolicy.DefinitionVersionProperties{
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
					"test": {
						Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
							AssignPermissions: to.Ptr(true),
						},
					},
				},
			},
		},
	}
	pd.UnsetAssignPermissionsOnParameter("test")
	assert.Nil(t, pd.Properties.Parameters["test"].Metadata.AssignPermissions)
}

func TestVersionFromDefinition(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		pd := &PolicyDefinitionVersion{
			DefinitionVersion: armpolicy.DefinitionVersion{
				Properties: &armpolicy.DefinitionVersionProperties{
					Version: to.Ptr("1.0.0"),
				},
			},
		}
		assert.Equal(t, "1.0.0", *pd.GetVersion())
	})
	t.Run("absent", func(t *testing.T) {
		pd := &PolicyDefinitionVersion{
			DefinitionVersion: armpolicy.DefinitionVersion{
				Properties: &armpolicy.DefinitionVersionProperties{
					Version: nil,
				},
			},
		}
		assert.Nil(t, pd.GetVersion())
	})
}
