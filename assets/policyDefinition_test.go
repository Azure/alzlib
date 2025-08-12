// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package assets

import (
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
)

func TestNormalizedRoleDefinitionResourceIds(t *testing.T) {
	pd := &PolicyDefinition{
		Definition: armpolicy.Definition{
			Properties: &armpolicy.DefinitionProperties{
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

func TestSetAssignPermissionsOnParameter(t *testing.T) {
	pd := &PolicyDefinition{
		Definition: armpolicy.Definition{
			Properties: &armpolicy.DefinitionProperties{
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

func TestUnsetAssignPermissionsOnParameter(t *testing.T) {
	pd := &PolicyDefinition{
		Definition: armpolicy.Definition{
			Properties: &armpolicy.DefinitionProperties{
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
