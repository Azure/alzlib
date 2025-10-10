// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"reflect"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func TestGetReferencedPolicyDefinitionNames(t *testing.T) {
	psd := NewPolicySetDefinition(armpolicy.SetDefinition{
		Properties: &armpolicy.SetDefinitionProperties{
			PolicyDefinitions: []*armpolicy.DefinitionReference{
				{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup" +
							"/providers/Microsoft.Authorization/policyDefinitions/policy1",
					),
				},
				{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup" +
							"/providers/Microsoft.Authorization/policyDefinitions/policy2",
					),
				},
			},
		},
	})

	expectedNames := []string{"policy1", "policy2"}

	names, err := psd.ReferencedPolicyDefinitionNames()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(names, expectedNames) {
		t.Fatalf("got %v, want %v", names, expectedNames)
	}
}

func TestGetPolicyDefinitionReferences(t *testing.T) {
	psd := NewPolicySetDefinition(armpolicy.SetDefinition{
		Properties: &armpolicy.SetDefinitionProperties{
			PolicyDefinitions: []*armpolicy.DefinitionReference{
				{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/" +
							"Microsoft.Authorization/policyDefinitions/policy1",
					),
				},
				{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/" +
							"Microsoft.Authorization/policyDefinitions/policy2",
					),
				},
			},
		},
	})
	expectedReferences := []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID: to.Ptr(
				"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup" +
					"/providers/Microsoft.Authorization/policyDefinitions/policy1",
			),
		},
		{
			PolicyDefinitionID: to.Ptr(
				"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup" +
					"/providers/Microsoft.Authorization/policyDefinitions/policy2",
			),
		},
	}
	references := psd.PolicyDefinitionReferences()
	assert.NotNil(t, references, "expected references to be non-nil")
	assert.Equal(t, expectedReferences, references)
}

func TestParameter(t *testing.T) {
	psd := NewPolicySetDefinition(armpolicy.SetDefinition{
		Properties: &armpolicy.SetDefinitionProperties{
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"param1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
				"param2": {
					Type: to.Ptr(armpolicy.ParameterTypeInteger),
				},
			},
		},
	})

	// Test existing parameter
	param1 := psd.Parameter("param1")
	assert.NotNil(t, param1, "expected parameter 'param1' to be non-nil")
	assert.Equal(t, armpolicy.ParameterTypeString, *param1.Type)

	// Test non-existing parameter
	param3 := psd.Parameter("param3")
	assert.Nil(t, param3, "expected parameter 'param3' to be nil")
}

func TestNewPolicySetDefinitionFromVersionValidateSuccess(t *testing.T) {
	versionID := "/subscriptions/00000000-0000-0000-0000-000000000000/providers/" +
		"Microsoft.Authorization/policySetDefinitions/myPolicySet/versions/1.0.0"
	displayName := "My Policy Set"
	description := "Policy set description"
	version := "1.0.0"

	psdVersion := armpolicy.SetDefinitionVersion{
		ID: to.Ptr(versionID),
		Properties: &armpolicy.SetDefinitionVersionProperties{
			DisplayName:       to.Ptr(displayName),
			Description:       to.Ptr(description),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
			Version:           to.Ptr(version),
		},
	}

	psd, err := NewPolicySetDefinitionFromVersionValidate(psdVersion)
	require.NoError(t, err)
	require.NotNil(t, psd)
	require.NotNil(t, psd.Properties)

	require.NotNil(t, psd.Name)
	assert.Equal(t, "myPolicySet", *psd.Name)
	require.NotNil(t, psd.Properties.DisplayName)
	assert.Equal(t, displayName, *psd.Properties.DisplayName)
	require.NotNil(t, psd.Properties.Description)
	assert.Equal(t, description, *psd.Properties.Description)
	require.NotNil(t, psd.Properties.Version)
	assert.Equal(t, version, *psd.Properties.Version)
	assert.NotNil(t, psd.Properties.Parameters)
	assert.NotNil(t, psd.Properties.PolicyDefinitions)
	assert.NotNil(t, psd.Properties.PolicyDefinitionGroups)
	assert.NotNil(t, psd.Properties.Metadata)
}

func TestNewPolicySetDefinitionFromVersionValidateMissingID(t *testing.T) {
	_, err := NewPolicySetDefinitionFromVersionValidate(armpolicy.SetDefinitionVersion{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "policy set definition ID must be set")
}

func TestNewPolicySetDefinitionFromVersionValidateInvalidResourceID(t *testing.T) {
	psdVersion := armpolicy.SetDefinitionVersion{
		ID: to.Ptr("invalid-resource-id"),
	}

	_, err := NewPolicySetDefinitionFromVersionValidate(psdVersion)
	require.Error(t, err)
	assert.ErrorContains(t, err, "parsing resource ID")
}

func TestNewPolicySetDefinitionFromVersionValidateValidationFailure(t *testing.T) {
	versionID := "/subscriptions/00000000-0000-0000-0000-000000000000/providers/" +
		"Microsoft.Authorization/policySetDefinitions/anotherPolicySet/versions/1.0.0"
	description := "Policy set description"

	psdVersion := armpolicy.SetDefinitionVersion{
		ID: to.Ptr(versionID),
		Properties: &armpolicy.SetDefinitionVersionProperties{
			Description:       to.Ptr(description),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
		},
	}

	_, err := NewPolicySetDefinitionFromVersionValidate(psdVersion)
	require.Error(t, err)
	assert.ErrorContains(t, err, "'properties.displayName' must not be nil")
}
