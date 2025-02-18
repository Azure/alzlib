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
		return nil, errors.New("PolicyAssignment.ReferencedPolicyDefinitionResourceId: policy assignment is nil, missing properties	or policy definition ID")
	}
	return arm.ParseResourceID(*pa.Properties.PolicyDefinitionID)
}

// ParameterValueAsString returns the value of a policy assignment parameter.
// We always expect the value to be a string as it's used in calculating the additional role assignments for
// policy parameters with the assignPermissions metadata set to true.
// Therefore the value should be an ARM resourceId.
func (pa *PolicyAssignment) ParameterValueAsString(paramName string) (string, error) {
	if pa == nil || pa.Properties == nil || pa.Properties.Parameters == nil {
		return "", fmt.Errorf("PolicyAssignment.ParameterValueAsString: assignment, assignment propertiers or parameters is nil %s", *pa.Name)
	}
	paParamVal, ok := pa.Properties.Parameters[paramName]
	if !ok {
		return "", fmt.Errorf("PolicyAssignment.ParameterValueAsString: parameter %s not found in policy assignment %s", paramName, *pa.Name)
	}
	if paParamVal.Value == nil {
		return "", fmt.Errorf("PolicyAssignment.ParameterValueAsString: parameter %s value field in policy assignment %s is nil", paramName, *pa.Name)
	}
	paParamValStr, ok := paParamVal.Value.(string)
	if !ok {
		return "", fmt.Errorf("PolicyAssignment.ParameterValueAsString: parameter %s value in policy assignment %s is not a string", paramName, *pa.Name)
	}
	return paParamValStr, nil
}

// ModifyPolicyAssignmentOption defines a functional option for modifying a policy assignment.
type ModifyPolicyAssignmentOption func(*armpolicy.Assignment)

// WithAssignmentParameters sets the parameters for the policy assignment.
func WithAssignmentParameters(parameters map[string]*armpolicy.ParameterValuesValue) ModifyPolicyAssignmentOption {
	return func(assignment *armpolicy.Assignment) {
		if assignment.Properties.Parameters == nil && len(parameters) > 0 {
			assignment.Properties.Parameters = make(map[string]*armpolicy.ParameterValuesValue, len(parameters))
		}
		for k, v := range parameters {
			assignment.Properties.Parameters[k] = v
		}
	}
}

// WithAssignmentEnforcementMode sets the enforcement mode for the policy assignment.
func WithAssignmentEnforcementMode(enforcementMode armpolicy.EnforcementMode) ModifyPolicyAssignmentOption {
	return func(assignment *armpolicy.Assignment) {
		assignment.Properties.EnforcementMode = &enforcementMode
	}
}

// WithAssignmentNonComplianceMessages sets the non-compliance messages for the policy assignment.
func WithAssignmentNonComplianceMessages(nonComplianceMessages []*armpolicy.NonComplianceMessage) ModifyPolicyAssignmentOption {
	return func(assignment *armpolicy.Assignment) {
		assignment.Properties.NonComplianceMessages = nonComplianceMessages
	}
}

// WithAssignmentResourceSelectors sets the resource selectors for the policy assignment.
func WithAssignmentResourceSelectors(resourceSelectors []*armpolicy.ResourceSelector) ModifyPolicyAssignmentOption {
	return func(assignment *armpolicy.Assignment) {
		assignment.Properties.ResourceSelectors = resourceSelectors
	}
}

// WithAssignmentOverrides sets the overrides for the policy assignment.
func WithAssignmentOverrides(overrides []*armpolicy.Override) ModifyPolicyAssignmentOption {
	return func(assignment *armpolicy.Assignment) {
		assignment.Properties.Overrides = overrides
	}
}

// WithAssignmentIdentity sets the identity for the policy assignment.
func WithAssignmentIdentity(identity *armpolicy.Identity) ModifyPolicyAssignmentOption {
	return func(assignment *armpolicy.Assignment) {
		assignment.Identity = identity
	}
}

// WithNotScopes sets the not scopes for the policy assignment.
func WithNotScopes(notScopes []*string) ModifyPolicyAssignmentOption {
	return func(assignment *armpolicy.Assignment) {
		assignment.Properties.NotScopes = notScopes
	}
}
