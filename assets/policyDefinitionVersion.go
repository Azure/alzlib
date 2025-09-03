// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// PolicyDefinitionVersion represents a version of a policy definition with version information.
// It embeds the armpolicy.DefinitionVersion struct and provides additional methods to work with it.
type PolicyDefinitionVersion struct {
	armpolicy.DefinitionVersion
}

// NewPolicyDefinitionVersion creates a new PolicyDefinitionVersion from an
// armpolicy.DefinitionVersion.
func NewPolicyDefinitionVersion(pd armpolicy.DefinitionVersion) *PolicyDefinitionVersion {
	return &PolicyDefinitionVersion{DefinitionVersion: pd}
}

// NewPolicyDefinitionVersionValidate creates a new PolicyDefinitionVersion instance and validates it.
func NewPolicyDefinitionVersionValidate(pd armpolicy.DefinitionVersion) (*PolicyDefinitionVersion, error) {
	pdObj := &PolicyDefinitionVersion{DefinitionVersion: pd}

	if err := ValidatePolicyDefinitionVersion(pdObj); err != nil {
		return nil, err
	}

	return pdObj, nil
}

// RoleDefinitionResourceIDs returns the role definition ids referenced in a policy definition
// if they exist.
// We marshall the policyRule as JSON and then unmarshal into a custom type.
func (pd *PolicyDefinitionVersion) RoleDefinitionResourceIDs() ([]string, error) {
	if pd == nil || pd.Properties == nil || pd.Properties.PolicyRule == nil {
		return nil, errors.New(
			"PolicyDefinition.RoleDefinitionResourceIds: policy definition is nil, missing properties or policy rule",
		)
	}

	j, err := json.Marshal(pd.Properties.PolicyRule)
	if err != nil {
		return nil, fmt.Errorf(
			"PolicyDefinition.RoleDefinitionResourceIds: could not marshal policy rule: %w",
			err,
		)
	}

	r := new(policyDefinitionRule)
	if err := json.Unmarshal(j, r); err != nil {
		// For append policies, the `then.details` field is an array, so we need to handle this case.
		// There are no roleDefinitionIds here anyway, so we can just return an empty slice.
		// This explains why the PolicyRule field if of type any.
		jsonerr := new(json.UnmarshalTypeError)
		if errors.As(err, &jsonerr) {
			if jsonerr.Value == "array" && jsonerr.Field == "then.details" {
				return []string{}, nil
			}
		}

		return nil, fmt.Errorf(
			"PolicyDefinition.RoleDefinitionResourceIds: could not unmarshal policy rule: %w",
			err,
		)
	}

	if r.Then.Details == nil || r.Then.Details.RoleDefinitionIDs == nil ||
		len(r.Then.Details.RoleDefinitionIDs) == 0 {
		return []string{}, nil
	}

	return r.Then.Details.RoleDefinitionIDs, nil
}

// NormalizedRoleDefinitionResourceIDs normalizes a role definition id by removing the version suffix
// (if present) and returning the resource id in the format:
// /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/{roleDefinitionId}.
func (pd *PolicyDefinitionVersion) NormalizedRoleDefinitionResourceIDs() ([]string, error) {
	rdids, err := pd.RoleDefinitionResourceIDs()
	if err != nil {
		return nil, err
	}

	normalized := make([]string, len(rdids))

	for i, rdid := range rdids {
		nrdid, err := normalizeRoleDefinitionID(rdid)
		if err != nil {
			return nil, err
		}

		normalized[i] = nrdid
	}

	return normalized, nil
}

// AssignPermissionsParameterNames returns a list of parameter names that have the AssignPermissions
// metadata field set to true.
func (pd *PolicyDefinitionVersion) AssignPermissionsParameterNames() ([]string, error) {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return nil, errors.New(
			"PolicyDefinition.AssignPermissionsParameterNames: policy definition is nil, missing properties or parameters",
		)
	}

	names := make([]string, 0)

	for name, param := range pd.Properties.Parameters {
		if param.Metadata == nil || param.Metadata.AssignPermissions == nil ||
			!*param.Metadata.AssignPermissions {
			continue
		}

		names = append(names, name)
	}

	return names, nil
}

// ParameterIsOptional checks if the parameter with the given name is optional.
func (pd *PolicyDefinitionVersion) ParameterIsOptional(name string) (bool, error) {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return false, errors.New(
			"PolicyDefinition.ParameterIsOptional: policy definition is nil, missing properties or parameters",
		)
	}

	param, ok := pd.Properties.Parameters[name]
	if !ok {
		return false, fmt.Errorf(
			"PolicyDefinition.ParameterIsOptional: parameter %s not found in policy definition",
			name,
		)
	}

	if param.DefaultValue == nil {
		return false, nil
	}

	return true, nil
}

// Parameter returns the parameter definition for the given name.
func (pd *PolicyDefinitionVersion) Parameter(name string) *armpolicy.ParameterDefinitionsValue {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return nil
	}

	ret, ok := pd.Properties.Parameters[name]
	if !ok {
		return nil
	}

	return ret
}

// SetAssignPermissionsOnParameter sets the AssignPermissions metadata field to true for the
// parameter with the given
// name.
func (pd *PolicyDefinitionVersion) SetAssignPermissionsOnParameter(parameterName string) {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return
	}

	param, ok := pd.Properties.Parameters[parameterName]
	if !ok {
		return
	}

	if param.Metadata == nil {
		param.Metadata = new(armpolicy.ParameterDefinitionsValueMetadata)
	}

	param.Metadata.AssignPermissions = to.Ptr(true)
}

// UnsetAssignPermissionsOnParameter removes the AssignPermissions metadata field for the parameter
// with the given name.
func (pd *PolicyDefinitionVersion) UnsetAssignPermissionsOnParameter(parameterName string) {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return
	}

	param, ok := pd.Properties.Parameters[parameterName]
	if !ok {
		return
	}

	if param.Metadata == nil {
		return
	}

	param.Metadata.AssignPermissions = nil
}

// GetVersion returns the version of the policy definition, if it exists.
// If the version is not set, it returns nil.
func (pd *PolicyDefinitionVersion) GetVersion() *string {
	if pd == nil || pd.Properties == nil {
		return nil
	}

	return pd.Properties.Version
}

// GetName returns the name of the policy definition version.
func (pd *PolicyDefinitionVersion) GetName() *string {
	if pd == nil {
		return nil
	}

	return pd.Name
}

// ValidatePolicyDefinitionVersion performs validation checks on the policy definition.
// To reduce the risk of nil pointer dereferences, it will create empty values for optional fields.
func ValidatePolicyDefinitionVersion(pd *PolicyDefinitionVersion) error {
	if pd == nil {
		return NewErrPropertyMustNotBeNil("PolicyDefinition")
	}

	if pd.Name == nil {
		return NewErrPropertyMustNotBeNil("name")
	}

	if *pd.Name == "" ||
		utf8.RuneCountInString(*pd.Name) > PolicyDefinitionNameMaxLength {
		return NewErrPropertyLength(
			"name",
			1,
			PolicyDefinitionNameMaxLength,
			utf8.RuneCountInString(*pd.Name),
		)
	}

	if pd.Properties == nil {
		return NewErrPropertyMustNotBeNil("properties")
	}

	if pd.Properties.Description == nil {
		return NewErrPropertyMustNotBeNil("properties.description")
	}

	if pd.Properties.DisplayName == nil {
		return NewErrPropertyMustNotBeNil("properties.displayName")
	}

	if pd.Properties.Parameters == nil {
		pd.Properties.Parameters = make(map[string]*armpolicy.ParameterDefinitionsValue)
	}

	if pd.Properties.DisplayName == nil {
		return NewErrPropertyMustNotBeNil("properties.displayName")
	}

	if pd.Properties.Description == nil {
		return NewErrPropertyMustNotBeNil("properties.description")
	}

	if pd.Properties.PolicyRule == nil {
		return NewErrPropertyMustNotBeNil("properties.policyRule")
	}

	if *pd.Properties.Description == "" ||
		utf8.RuneCountInString(*pd.Properties.Description) > PolicyDefinitionDescriptionMaxLength {
		return NewErrPropertyLength(
			"properties.description",
			1,
			PolicyDefinitionDescriptionMaxLength,
			utf8.RuneCountInString(*pd.Properties.Description),
		)
	}

	if *pd.Properties.DisplayName == "" ||
		utf8.RuneCountInString(*pd.Properties.DisplayName) > PolicyDefinitionDisplayNameMaxLength {
		return NewErrPropertyLength(
			"properties.displayName",
			1,
			PolicyDefinitionDisplayNameMaxLength,
			utf8.RuneCountInString(*pd.Properties.DisplayName),
		)
	}

	if pd.Properties.Mode == nil {
		pd.Properties.Mode = to.Ptr(policyDefinitionModeDefault)
	}

	if pd.Properties.Metadata == nil {
		pd.Properties.Metadata = any(map[string]any{})
	}

	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for type PolicySetDefinition.
// It performs validity checks on mandatory fields as well as some validation checks on certain
// fields.
func (pd *PolicyDefinitionVersion) UnmarshalJSON(data []byte) error {
	if err := pd.DefinitionVersion.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("PolicyDefinition.UnmarshalJSON: %w", err)
	}

	return ValidatePolicyDefinitionVersion(pd)
}
