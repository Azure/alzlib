// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestResolveParameterCaseInsensitive covers the built-in Windows AMA/DCR shape, where the
// initiative passes `DcrResourceId` to a definition declaring `dcrResourceId`.
func TestResolveParameterCaseInsensitive(t *testing.T) {
	pd := &PolicyDefinition{
		Definition: armpolicy.Definition{
			Properties: &armpolicy.DefinitionProperties{
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
					"dcrResourceId": {Type: to.Ptr(armpolicy.ParameterTypeString)},
				},
			},
		},
	}

	name, param, found, err := pd.ResolveParameter("dcrResourceId")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "dcrResourceId", name)
	assert.NotNil(t, param)

	name, param, found, err = pd.ResolveParameter("DcrResourceId")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "dcrResourceId", name)
	assert.NotNil(t, param)
	assert.NotNil(t, pd.Parameter("DcrResourceId"))

	_, _, found, err = pd.ResolveParameter("minPort")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, pd.Parameter("minPort"))
}

func TestResolveParameterAmbiguous(t *testing.T) {
	pd := &PolicyDefinition{
		Definition: armpolicy.Definition{
			Properties: &armpolicy.DefinitionProperties{
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
					"dcrResourceId": {Type: to.Ptr(armpolicy.ParameterTypeString)},
					"DCRRESOURCEID": {Type: to.Ptr(armpolicy.ParameterTypeString)},
				},
			},
		},
	}

	_, _, found, err := pd.ResolveParameter("DcrResourceId")
	require.Error(t, err)
	assert.False(t, found)
	require.ErrorContains(t, err, "is ambiguous")
	assert.Nil(t, pd.Parameter("DcrResourceId"))
}

// TestAssignPermissionsAndOptionalParameterCaseInsensitive asserts that the parameter-name based
// helpers agree with Parameter() on casing, so a case-only variant does not silently no-op.
func TestAssignPermissionsAndOptionalParameterCaseInsensitive(t *testing.T) {
	pd := &PolicyDefinition{
		Definition: armpolicy.Definition{
			Properties: &armpolicy.DefinitionProperties{
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
					"dcrResourceId": {Type: to.Ptr(armpolicy.ParameterTypeString)},
				},
			},
		},
	}

	optional, err := pd.ParameterIsOptional("DcrResourceId")
	require.NoError(t, err)
	assert.False(t, optional)

	pd.SetAssignPermissionsOnParameter("DcrResourceId")
	require.NotNil(t, pd.Properties.Parameters["dcrResourceId"].Metadata)
	assert.True(t, *pd.Properties.Parameters["dcrResourceId"].Metadata.AssignPermissions)

	pd.UnsetAssignPermissionsOnParameter("DCRRESOURCEID")
	assert.Nil(t, pd.Properties.Parameters["dcrResourceId"].Metadata.AssignPermissions)

	_, err = pd.ParameterIsOptional("minPort")
	require.ErrorContains(t, err, "not found in policy definition")
}

func TestResolveParameterNilReceiverAndProperties(t *testing.T) {
	var pd *PolicyDefinition

	_, _, found, err := pd.ResolveParameter("dcrResourceId")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, pd.Parameter("dcrResourceId"))

	pd = &PolicyDefinition{Definition: armpolicy.Definition{}}

	_, _, found, err = pd.ResolveParameter("dcrResourceId")
	require.NoError(t, err)
	assert.False(t, found)
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
	require.NoError(t, err)
	assert.NotNil(t, pd)
	assert.Equal(t, "myPolicy", *pd.Name)
	assert.Equal(t, "1.0.0", *pd.Properties.Version)
}

func TestNewPolicyDefinitionFromVersionMissingID(t *testing.T) {
	_, err := NewPolicyDefinitionFromVersion(armpolicy.DefinitionVersion{})
	require.Error(t, err)
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
	require.NoError(t, err)
	assert.NotNil(t, pd)
	assert.Equal(t, longDisplayName, *pd.Properties.DisplayName)
}
