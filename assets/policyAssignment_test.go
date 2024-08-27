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
			PolicyDefinitionID: to.Ptr("/subscriptions/123/resourceGroups/rg1/providers/Microsoft.Authorization/policyDefinitions/pd1"),
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
	resourceID, err := pa.ReferencedPolicyDefinitionResourceId()
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
	assert.Equal(t, paramValue, expectedValue)

	paramName = "param2"
	_, err = pa.ParameterValueAsString(paramName)
	require.Error(t, err)
	expectedError := fmt.Sprintf("parameter %s value in policy assignment %s is not a string", paramName, *pa.Name)
	assert.ErrorContains(t, err, expectedError)

	paramName = "param3"
	_, err = pa.ParameterValueAsString(paramName)
	require.Error(t, err)

	expectedError = fmt.Sprintf("parameter %s not found in policy assignment %s", paramName, *pa.Name)
	assert.ErrorContains(t, err, expectedError)
}
