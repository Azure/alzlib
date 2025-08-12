// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package assets

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

const (
	// PolicyAssignmentNameMaxLength is the maximum length of a policy assignment name, at MG scope this is 24.
	PolicyAssignmentNameMaxLength = 24
	// PolicyAssignmentDisplayNameMaxLength is the maximum length of a policy assignment display name.
	PolicyAssignmentDisplayNameMaxLength = 128
	// PolicyAssignmentDescriptionMaxLength is the maximum length of a policy assignment description.
	PolicyAssignmentDescriptionMaxLength = 512
)

// PolicyAssignment represents a policy assignment in Azure.
// It wraps the armpolicy.Assignment type and provides additional methods for validation and
// working with policy assignments.
type PolicyAssignment struct {
	armpolicy.Assignment
}

// NewPolicyAssignment creates a new PolicyAssignment instance from an armpolicy.Assignment.
// The caller is responsible for ensuring that the policy assignment is valid.
// Use either the UnmarshalJSON method, or the ValidatePolicyAssignment function to validate the
// assignment.
func NewPolicyAssignment(pa armpolicy.Assignment) *PolicyAssignment {
	return &PolicyAssignment{pa}
}

// NewPolicyAssignmentValidate creates a new PolicyAssignment instance and validates it.
func NewPolicyAssignmentValidate(pa armpolicy.Assignment) (*PolicyAssignment, error) {
	paObj := &PolicyAssignment{pa}
	if err := ValidatePolicyAssignment(paObj); err != nil {
		return nil, fmt.Errorf("NewPolicyAssignmentValidate: %w", err)
	}

	return paObj, nil
}

// IdentityType returns the identity type of the policy assignment.
func (pa *PolicyAssignment) IdentityType() armpolicy.ResourceIdentityType {
	return *pa.Identity.Type
}

// ReferencedPolicyDefinitionResourceID returns the resource ID of the policy definition referenced by
// the policy assignment.
func (pa *PolicyAssignment) ReferencedPolicyDefinitionResourceID() (*arm.ResourceID, error) {
	return arm.ParseResourceID(*pa.Properties.PolicyDefinitionID)
}

// ParameterValueAsString returns the value of a policy assignment parameter.
// We always expect the value to be a string as it's used in calculating the additional role
// assignments for
// policy parameters with the assignPermissions metadata set to true.
// Therefore the value should be an ARM resourceId.
func (pa *PolicyAssignment) ParameterValueAsString(paramName string) (string, error) {
	paParamVal, ok := pa.Properties.Parameters[paramName]
	if !ok {
		return "", fmt.Errorf(
			"PolicyAssignment.ParameterValueAsString: parameter %s not found in policy assignment %s",
			paramName,
			*pa.Name,
		)
	}

	if paParamVal.Value == nil {
		return "", fmt.Errorf(
			"PolicyAssignment.ParameterValueAsString: parameter %s value field in policy assignment %s is nil",
			paramName,
			*pa.Name,
		)
	}

	paParamValStr, ok := paParamVal.Value.(string)
	if !ok {
		return "", fmt.Errorf(
			"PolicyAssignment.ParameterValueAsString: parameter %s value in policy assignment %s is not a string",
			paramName,
			*pa.Name,
		)
	}

	return paParamValStr, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for type PolicyAssignment.
// It performs validity checks on mandatory fields as well as some validation checks on certain
// fields.
func (pa *PolicyAssignment) UnmarshalJSON(data []byte) error {
	if err := pa.Assignment.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("PolicyAssignment.UnmarshalJSON: %w", err)
	}

	return ValidatePolicyAssignment(pa)
}

// ValidatePolicyAssignment performs validation checks on the policy assignment.
// To reduce the risk of nil pointer dereferences, it will create empty values for optional fields.
func ValidatePolicyAssignment(pa *PolicyAssignment) error {
	if pa == nil {
		return errors.New("ValidatePolicyAssignment: policy assignment is nil")
	}

	if pa.Name == nil {
		return errors.New("ValidatePolicyAssignment: name must not be nil")
	}

	if *pa.Name == "" || utf8.RuneCountInString(*pa.Name) > PolicyAssignmentNameMaxLength {
		return fmt.Errorf(
			"ValidatePolicyAssignment: name length is %d, must be between 1 and %d due to assignment at management group scope",
			utf8.RuneCountInString(*pa.Name),
			PolicyAssignmentNameMaxLength,
		)
	}

	if pa.Properties == nil {
		return errors.New("ValidatePolicyAssignment: properties must not be nil")
	}

	if pa.Properties.PolicyDefinitionID == nil {
		return errors.New("ValidatePolicyAssignment: policy definition ID must not be nil")
	}

	if pa.Properties.DisplayName == nil {
		return errors.New("ValidatePolicyAssignment: display name must not be nil")
	}

	if *pa.Properties.DisplayName == "" ||
		utf8.RuneCountInString(*pa.Properties.DisplayName) > PolicyAssignmentDisplayNameMaxLength {
		return fmt.Errorf(
			"ValidatePolicyAssignment: display name length is %d, must be between 1 and %d",
			utf8.RuneCountInString(*pa.Properties.DisplayName),
			PolicyAssignmentDisplayNameMaxLength,
		)
	}

	if pa.Properties.Description == nil {
		return errors.New("ValidatePolicyAssignment: description must not be nil")
	}

	if *pa.Properties.Description == "" ||
		utf8.RuneCountInString(*pa.Properties.Description) > PolicyAssignmentDescriptionMaxLength {
		return fmt.Errorf(
			"ValidatePolicyAssignment: description length is %d, must be between 1 and %d",
			utf8.RuneCountInString(*pa.Properties.Description),
			PolicyAssignmentDescriptionMaxLength,
		)
	}

	if pa.Properties.Metadata == nil {
		pa.Properties.Metadata = any(map[string]any{})
	}

	if pa.Properties.EnforcementMode == nil {
		pa.Properties.EnforcementMode = to.Ptr(armpolicy.EnforcementModeDefault)
	}

	if pa.Identity == nil {
		pa.Identity = &armpolicy.Identity{
			Type:                   to.Ptr(armpolicy.ResourceIdentityTypeNone),
			UserAssignedIdentities: make(map[string]*armpolicy.UserAssignedIdentitiesValue),
		}
	}

	if pa.Properties.ResourceSelectors == nil {
		pa.Properties.ResourceSelectors = make([]*armpolicy.ResourceSelector, 0)
	}

	if pa.Properties.Overrides == nil {
		pa.Properties.Overrides = make([]*armpolicy.Override, 0)
	}

	if pa.Properties.Parameters == nil {
		pa.Properties.Parameters = make(map[string]*armpolicy.ParameterValuesValue)
	}

	return nil
}
