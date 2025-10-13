// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

const (
	// PolicySetDefinitionDisplayNameMaxLength is the maximum length of the display name for a policy set definition.
	PolicySetDefinitionDisplayNameMaxLength = 128
	// PolicySetDefinitionDescriptionMaxLength is the maximum length of the description for a policy set definition.
	PolicySetDefinitionDescriptionMaxLength = 512
	// PolicySetDefinitionNameMaxLength is the maximum length of the name for a policy set definition.
	PolicySetDefinitionNameMaxLength = 64
	// policySetDefinitionCollectionCapacity is the initial capacity for collections in a policy set definition.
	policySetDefinitionCollectionCapacity = 20
)

// PolicySetDefinition represents a policy set definition and embeds the armpolicy.SetDefinition struct.
type PolicySetDefinition struct {
	armpolicy.SetDefinition
}

// NewPolicySetDefinition creates a new PolicySetDefinition from an armpolicy.SetDefinition.
func NewPolicySetDefinition(psd armpolicy.SetDefinition) *PolicySetDefinition {
	return &PolicySetDefinition{psd}
}

// NewPolicySetDefinitionValidate creates a new PolicySetDefinition instance and validates it.
func NewPolicySetDefinitionValidate(psd armpolicy.SetDefinition) (*PolicySetDefinition, error) {
	psdObj := &PolicySetDefinition{psd}
	if err := ValidatePolicySetDefinition(psdObj); err != nil {
		return nil, fmt.Errorf("NewPolicySetDefinitionValidate: %w", err)
	}

	return psdObj, nil
}

// NewPolicySetDefinitionFromVersionValidate creates a new PolicySetDefinitionVersion instance and validates it.
func NewPolicySetDefinitionFromVersionValidate(psd armpolicy.SetDefinitionVersion) (*PolicySetDefinition, error) {
	if psd.ID == nil || *psd.ID == "" {
		return nil, errors.New("NewPolicySetDefinitionFromVersionValidate: policy set definition ID must be set")
	}

	if psd.Properties == nil {
		return nil, errors.New("NewPolicySetDefinitionFromVersionValidate: policy set definition properties must be set")
	}

	if psd.Properties.Version == nil || *psd.Properties.Version == "" {
		return nil, errors.New("NewPolicySetDefinitionFromVersionValidate: policy set definition version must be set")
	}

	resID, err := arm.ParseResourceID(*psd.ID)
	if err != nil {
		return nil, fmt.Errorf("NewPolicySetDefinitionFromVersionValidate: parsing resource ID %s: %w", *psd.ID, err)
	}

	policyName := resID.Parent.Name

	jsonBytes, err := json.Marshal(psd)
	if err != nil {
		return nil, fmt.Errorf(
			"NewPolicySetDefinitionFromVersionValidate: marshalling policy set definition version: %w", err,
		)
	}

	var psdDef armpolicy.SetDefinition
	if err := json.Unmarshal(jsonBytes, &psdDef); err != nil {
		return nil, fmt.Errorf("NewPolicySetDefinitionFromVersionValidate: unmarshalling to policy set definition: %w", err)
	}

	psdDef.Name = &policyName

	return NewPolicySetDefinitionValidate(psdDef)
}

// ReferencedPolicyDefinitionNames returns the names of the policy definitions referenced by the policy set definition.
func (psd *PolicySetDefinition) ReferencedPolicyDefinitionNames() ([]string, error) {
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
func (psd *PolicySetDefinition) PolicyDefinitionReferences() []*armpolicy.DefinitionReference {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil
	}

	return psd.Properties.PolicyDefinitions
}

// Parameter returns the parameter definition for the given name.
func (psd *PolicySetDefinition) Parameter(name string) *armpolicy.ParameterDefinitionsValue {
	if psd == nil || psd.Properties == nil || psd.Properties.Parameters == nil {
		return nil
	}

	ret, ok := psd.Properties.Parameters[name]
	if !ok {
		return nil
	}

	return ret
}

// GetVersion returns the version of the policy definition, if it exists.
// If the version is not set, it returns nil.
func (psd *PolicySetDefinition) GetVersion() *string {
	if psd == nil || psd.Properties == nil {
		return nil
	}

	return psd.Properties.Version
}

// GetName returns the name of the policy definition version.
func (psd *PolicySetDefinition) GetName() *string {
	if psd == nil {
		return nil
	}

	return psd.Name
}

// ValidatePolicySetDefinition performs validation checks on the policy set definition.
// To reduce the risk of nil pointer dereferences, it will create empty values for optional fields.
func ValidatePolicySetDefinition(psd *PolicySetDefinition) error {
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
func (psd *PolicySetDefinition) UnmarshalJSON(data []byte) error {
	if err := psd.SetDefinition.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("PolicySetDefinition.UnmarshalJSON: %w", err)
	}

	return ValidatePolicySetDefinition(psd)
}
