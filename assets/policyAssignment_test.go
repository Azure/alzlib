// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityType(t *testing.T) {
	pa := NewPolicyAssignment(armpolicy.Assignment{
		Identity: &armpolicy.Identity{
			Type: to.Ptr(armpolicy.ResourceIdentityTypeUserAssigned),
		},
	})
	expectedType := armpolicy.ResourceIdentityTypeUserAssigned

	identityType := pa.IdentityType()

	if identityType != expectedType {
		t.Fatalf("got %v, want %v", identityType, expectedType)
	}
}

func TestReferencedPolicyDefinitionResourceId(t *testing.T) {
	pa := NewPolicyAssignment(armpolicy.Assignment{
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr(
				"/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1",
			),
		},
	})
	expectedResourceID := &arm.ResourceID{
		SubscriptionID:    "123",
		ResourceGroupName: "rg1",
		Provider:          "Microsoft.Authorization",
		ResourceType: arm.ResourceType{
			Namespace: "Microsoft.Authorization",
			Type:      "policyDefinitions",
			Types:     []string{},
		},
		Name: "pd1",
	}

	resourceID, _, err := pa.ReferencedPolicyDefinitionResourceIDAndVersion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if reflect.DeepEqual(resourceID, expectedResourceID) {
		t.Fatalf("got %v, want %v", resourceID, expectedResourceID)
	}
}

func TestGetParameterValueAsString(t *testing.T) {
	pa := NewPolicyAssignment(armpolicy.Assignment{
		Name: to.Ptr("testAssignment"),
		Properties: &armpolicy.AssignmentProperties{
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"param1": {
					Value: "value1",
				},
				"param2": {
					Value: 123, // Invalid value, should be a string
				},
			},
		},
	})
	paramName := "param1"
	expectedValue := "value1"
	paramValue, err := pa.ParameterValueAsString(paramName)
	require.NoError(t, err)
	assert.Equal(t, expectedValue, paramValue)

	paramName = "param2"
	_, err = pa.ParameterValueAsString(paramName)
	require.Error(t, err)

	expectedError := fmt.Sprintf(
		"parameter %s value in policy assignment %s is not a string",
		paramName,
		*pa.Name,
	)
	require.ErrorContains(t, err, expectedError)

	paramName = "param3"
	_, err = pa.ParameterValueAsString(paramName)
	require.Error(t, err)

	expectedError = fmt.Sprintf("parameter %s not found in policy assignment %s", paramName, *pa.Name)
	require.ErrorContains(t, err, expectedError)
}

func TestValidatePolicyAssignment(t *testing.T) {
	tests := []struct {
		name        string
		assignment  armpolicy.Assignment
		expectedErr string
	}{
		{
			name: "Valid PolicyAssignment",
			assignment: armpolicy.Assignment{
				Name: to.Ptr("validName"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1",
					),
					DisplayName: to.Ptr("Valid Display Name"),
					Description: to.Ptr("Valid Description"),
				},
			},
			expectedErr: "",
		},
		{
			name: "Nil Name",
			assignment: armpolicy.Assignment{
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1",
					),
					DisplayName: to.Ptr("Valid Display Name"),
					Description: to.Ptr("Valid Description"),
				},
			},
			expectedErr: "property 'name' must not be nil",
		},
		{
			name: "Empty Name",
			assignment: armpolicy.Assignment{
				Name: to.Ptr(""),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1",
					),
					DisplayName: to.Ptr("Valid Display Name"),
					Description: to.Ptr("Valid Description"),
				},
			},
			expectedErr: "name length is 0, must be between 1 and 24",
		},
		{
			name: "Nil Properties",
			assignment: armpolicy.Assignment{
				Name: to.Ptr("validName"),
			},
			expectedErr: "property 'properties' must not be nil",
		},
		{
			name: "Nil PolicyDefinitionID",
			assignment: armpolicy.Assignment{
				Name: to.Ptr("validName"),
				Properties: &armpolicy.AssignmentProperties{
					DisplayName: to.Ptr("Valid Display Name"),
					Description: to.Ptr("Valid Description"),
				},
			},
			expectedErr: "property 'properties.policyDefinitionID' must not be nil",
		},
		{
			name: "Nil DisplayName",
			assignment: armpolicy.Assignment{
				Name: to.Ptr("validName"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1",
					),
					Description: to.Ptr("Valid Description"),
				},
			},
			expectedErr: "property 'properties.displayName' must not be nil",
		},
		{
			name: "Empty DisplayName",
			assignment: armpolicy.Assignment{
				Name: to.Ptr("validName"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1",
					),
					DisplayName: to.Ptr(""),
					Description: to.Ptr("Valid Description"),
				},
			},
			expectedErr: "property 'properties.displayName' length must be between 1 and 128, but is 0",
		},
		{
			name: "Nil Description",
			assignment: armpolicy.Assignment{
				Name: to.Ptr("validName"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1",
					),
					DisplayName: to.Ptr("Valid Display Name"),
				},
			},
			expectedErr: "property 'properties.description' must not be nil",
		},
		{
			name: "Empty Description",
			assignment: armpolicy.Assignment{
				Name: to.Ptr("validName"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(
						"/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1",
					),
					DisplayName: to.Ptr("Valid Display Name"),
					Description: to.Ptr(""),
				},
			},
			expectedErr: "property 'properties.description' length must be between 1 and 512, but is 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := NewPolicyAssignment(tt.assignment)

			err := ValidatePolicyAssignment(pa)
			if tt.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}
