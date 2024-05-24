// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

type PolicyAssignment struct {
	armpolicy.Assignment
}

func NewPolicyAssignment(pa armpolicy.Assignment) *PolicyAssignment {
	return &PolicyAssignment{pa}
}

func (pa *PolicyAssignment) IdentityType() armpolicy.ResourceIdentityType {
	if pa.Identity == nil || pa.Identity.Type == nil || *pa.Identity.Type == "None" {
		return armpolicy.ResourceIdentityTypeNone
	}
	return *pa.Identity.Type
}

func (pa *PolicyAssignment) ReferencedPolicyDefinitionResourceId() (*arm.ResourceID, error) {
	if pa == nil || pa.Properties == nil || pa.Properties.PolicyDefinitionID == nil {
		return nil, errors.New("policy assignment is nil, missing properties	or policy definition ID")
	}
	return arm.ParseResourceID(*pa.Properties.PolicyDefinitionID)
}

// GetParameterValueAsString returns the value of a policy assignment parameter.
// We always expect the value to be a string as it's used in calculating the additional role assignments for
// policy parameters with the assignPermissions metadata set to true.
// Therefore the value should be an ARM resourceId.
func (pa *PolicyAssignment) GetParameterValueAsString(paramName string) (string, error) {
	if pa == nil || pa.Properties == nil || pa.Properties.Parameters == nil {
		return "", fmt.Errorf("assignment, assignment propertiers or parameters is nil %s", *pa.Name)
	}
	paParamVal, ok := pa.Properties.Parameters[paramName]
	if !ok {
		return "", fmt.Errorf("parameter %s not found in policy assignment %s", paramName, *pa.Name)
	}
	if paParamVal.Value == nil {
		return "", fmt.Errorf("parameter %s value field in policy assignment %s is nil", paramName, *pa.Name)
	}
	paParamValStr, ok := paParamVal.Value.(string)
	if !ok {
		return "", fmt.Errorf("parameter %s value in policy assignment %s is not a string", paramName, *pa.Name)
	}
	return paParamValStr, nil
}
