// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// PolicySetDefinitionVersion represents a version of a policy set definition with version
// information. It embeds the armpolicy.SetDefinitionVersion struct and provides additional methods
// to work with it.
type PolicySetDefinitionVersion struct {
	armpolicy.SetDefinitionVersion
}

// NewPolicySetDefinitionVersion creates a new PolicySetDefinitionVersion from an armpolicy.SetDefinitionVersion.
func NewPolicySetDefinitionVersion(psd armpolicy.SetDefinitionVersion) *PolicySetDefinitionVersion {
	return &PolicySetDefinitionVersion{psd}
}

// NewPolicySetDefinitionVersionValidate creates a new PolicySetDefinitionVersion instance and validates it.
func NewPolicySetDefinitionVersionValidate(psd armpolicy.SetDefinitionVersion) (*PolicySetDefinitionVersion, error) {
	psdObj := &PolicySetDefinitionVersion{psd}
	if err := ValidatePolicySetDefinitionVersion(psdObj); err != nil {
		return nil, fmt.Errorf("NewPolicySetDefinitionVersionValidate: %w", err)
	}

	return psdObj, nil
}

// ReferencedPolicyDefinitionNames returns the names of the policy definitions referenced by the policy set definition.
func (psd *PolicySetDefinitionVersion) ReferencedPolicyDefinitionNames() ([]string, error) {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil, errors.New("policy set definition is nil, missing properties or policy definitions")
	}

	names := make([]string, len(psd.Properties.PolicyDefinitions))

	for i, pd := range psd.Properties.PolicyDefinitions {
		resID, err := arm.ParseResourceID(*pd.PolicyDefinitionID)
		if err != nil {
			return nil, err
		}

		names[i] = resID.Name
	}

	return names, nil
}

// PolicyDefinitionReferences returns the policy definition references for the policy set definition.
func (psd *PolicySetDefinitionVersion) PolicyDefinitionReferences() []*armpolicy.DefinitionReference {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil
	}

	return psd.Properties.PolicyDefinitions
}

// Parameter returns the parameter definition for the given name.
func (psd *PolicySetDefinitionVersion) Parameter(name string) *armpolicy.ParameterDefinitionsValue {
	if psd == nil || psd.Properties == nil || psd.Properties.Parameters == nil {
		return nil
	}

	ret, ok := psd.Properties.Parameters[name]
	if !ok {
		return nil
	}

	return ret
}

// GetName returns the name of the policy set definition.
func (psd *PolicySetDefinitionVersion) GetName() *string {
	if psd == nil {
		return nil
	}

	return psd.Name
}

// GetVersion returns the version of the policy set definition.
func (psd *PolicySetDefinitionVersion) GetVersion() *string {
	if psd == nil || psd.Properties == nil {
		return nil
	}

	return psd.Properties.Version
}

// ValidatePolicySetDefinitionVersion performs validation checks on the policy set definition.
// To reduce the risk of nil pointer dereferences, it will create empty values for optional fields.
func ValidatePolicySetDefinitionVersion(psd *PolicySetDefinitionVersion) error {
	if psd == nil {
		return NewErrPropertyMustNotBeNil("PolicySetDefinition")
	}

	if psd.Name == nil {
		return NewErrPropertyMustNotBeNil("name")
	}

	if *psd.Name == "" || utf8.RuneCountInString(*psd.Name) > PolicySetDefinitionNameMaxLength {
		return fmt.Errorf(
			"ValidatePolicySetDefinition: name length is %d, must be between 1 and %d",
			utf8.RuneCountInString(*psd.Name),
			PolicySetDefinitionNameMaxLength,
		)
	}

	if psd.Properties == nil {
		return NewErrPropertyMustNotBeNil("properties")
	}

	if psd.Properties.Description == nil {
		return NewErrPropertyMustNotBeNil("properties.description")
	}

	if psd.Properties.DisplayName == nil {
		return NewErrPropertyMustNotBeNil("properties.displayName")
	}

	if psd.Properties.Parameters == nil {
		psd.Properties.Parameters = make(map[string]*armpolicy.ParameterDefinitionsValue)
	}

	if psd.Properties.DisplayName == nil {
		return NewErrPropertyMustNotBeNil("properties.displayName")
	}

	if psd.Properties.Description == nil {
		return NewErrPropertyMustNotBeNil("properties.description")
	}

	if *psd.Properties.Description == "" ||
		utf8.RuneCountInString(*psd.Properties.Description) > PolicySetDefinitionDescriptionMaxLength {
		return NewErrPropertyLength(
			"properties.description",
			1,
			PolicySetDefinitionDescriptionMaxLength,
			utf8.RuneCountInString(*psd.Properties.Description),
		)
	}

	if *psd.Properties.DisplayName == "" ||
		utf8.RuneCountInString(*psd.Properties.DisplayName) > PolicySetDefinitionDisplayNameMaxLength {
		return NewErrPropertyLength(
			"properties.displayName",
			1,
			PolicySetDefinitionDisplayNameMaxLength,
			utf8.RuneCountInString(*psd.Properties.DisplayName),
		)
	}

	if psd.Properties.PolicyDefinitions == nil {
		psd.Properties.PolicyDefinitions = make([]*armpolicy.DefinitionReference, 0, policySetDefinitionCollectionCapacity)
	}

	if psd.Properties.PolicyDefinitionGroups == nil {
		psd.Properties.PolicyDefinitionGroups = make([]*armpolicy.DefinitionGroup, 0, policySetDefinitionCollectionCapacity)
	}

	if psd.Properties.Metadata == nil {
		psd.Properties.Metadata = any(map[string]any{})
	}

	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for type PolicySetDefinition.
// It performs validity checks on mandatory fields as well as some validation checks on certain
// fields.
func (psd *PolicySetDefinitionVersion) UnmarshalJSON(data []byte) error {
	if err := psd.SetDefinitionVersion.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("PolicySetDefinition.UnmarshalJSON: %w", err)
	}

	return ValidatePolicySetDefinitionVersion(psd)
}
