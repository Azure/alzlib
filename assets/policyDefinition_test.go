// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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

func TestNewPolicyDefinitionFromVersionSuccess(t *testing.T) {
	versionID := "/subscriptions/00000000-0000-0000-0000-000000000000/providers/" +
		"Microsoft.Authorization/policyDefinitions/myPolicy/versions/1.0.0"

	pdVersion := armpolicy.DefinitionVersion{
		ID: to.Ptr(versionID),
		Properties: &armpolicy.DefinitionVersionProperties{
			DisplayName: to.Ptr("My Policy"),
			Description: to.Ptr("Policy description"),
			PolicyRule:  map[string]any{"if": map[string]any{"field": "type", "equals": "Microsoft.Resources/subscriptions"}, "then": map[string]any{"effect": "audit"}},
			Version:     to.Ptr("1.0.0"),
		},
	}

	pd, err := NewPolicyDefinitionFromVersion(pdVersion)
	assert.NoError(t, err)
	assert.NotNil(t, pd)
	assert.Equal(t, "myPolicy", *pd.Name)
	assert.Equal(t, "1.0.0", *pd.Properties.Version)
}

func TestNewPolicyDefinitionFromVersionMissingID(t *testing.T) {
	_, err := NewPolicyDefinitionFromVersion(armpolicy.DefinitionVersion{})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "policy definition ID must be set")
}

func TestNewPolicyDefinitionFromVersionNoValidation(t *testing.T) {
	// A definition with a display name exceeding the documented 128-char limit
	// should still succeed because the non-validating constructor is used.
	versionID := "/subscriptions/00000000-0000-0000-0000-000000000000/providers/" +
		"Microsoft.Authorization/policyDefinitions/myPolicy/versions/1.0.0"
	longDisplayName := "[Preview]: Microsoft Managed DevOps Pools should be provided with valid subnet resource in order to configure with own virtual network."

	pdVersion := armpolicy.DefinitionVersion{
		ID: to.Ptr(versionID),
		Properties: &armpolicy.DefinitionVersionProperties{
			DisplayName: to.Ptr(longDisplayName),
			Description: to.Ptr("Description"),
			PolicyRule:  map[string]any{"if": map[string]any{"field": "type", "equals": "Microsoft.Resources/subscriptions"}, "then": map[string]any{"effect": "audit"}},
			Version:     to.Ptr("1.0.0"),
		},
	}

	pd, err := NewPolicyDefinitionFromVersion(pdVersion)
	assert.NoError(t, err)
	assert.NotNil(t, pd)
	assert.Equal(t, longDisplayName, *pd.Properties.DisplayName)
}
