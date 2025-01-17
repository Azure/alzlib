// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

type PolicyDefinition struct {
	armpolicy.Definition
}

func NewPolicyDefinition(pd armpolicy.Definition) *PolicyDefinition {
	return &PolicyDefinition{pd}
}

// policyDefinitionRule represents the opinionated rule section of a policy definition.
// This is used to determine the role assignments that need to be created,
// therefore we only care about the `then.details.roleDefinitionIds` field.
type policyDefinitionRule struct {
	Then *struct {
		Details *struct {
			RoleDefinitionIds []string `json:"roleDefinitionIds,omitempty"`
		} `json:"details"`
	} `json:"then"`
}

// RoleDefinitionResourceIds returns the role definition ids referenced in a policy definition
// if they exist.
// We marshall the policyRule as JSON and then unmarshal into a custom type.
func (pd *PolicyDefinition) RoleDefinitionResourceIds() ([]string, error) {
	if pd == nil || pd.Properties == nil || pd.Properties.PolicyRule == nil {
		return nil, errors.New("PolicyDefinition.RoleDefinitionResourceIds: policy definition is nil, missing properties or policy rule")
	}
	j, err := json.Marshal(pd.Properties.PolicyRule)
	if err != nil {
		return nil, fmt.Errorf("PolicyDefinition.RoleDefinitionResourceIds: could not marshal policy rule: %w", err)
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
		return nil, fmt.Errorf("PolicyDefinition.RoleDefinitionResourceIds: could not unmarshal policy rule: %w", err)
	}
	if r.Then.Details == nil || r.Then.Details.RoleDefinitionIds == nil || len(r.Then.Details.RoleDefinitionIds) == 0 {
		return []string{}, nil
	}
	return r.Then.Details.RoleDefinitionIds, nil
}

func (pd *PolicyDefinition) NormalizedRoleDefinitionResourceIds() ([]string, error) {
	rdids, err := pd.RoleDefinitionResourceIds()
	if err != nil {
		return nil, err
	}
	normalized := make([]string, len(rdids))
	for i, rdid := range rdids {
		nrdid, err := normalizeRoleDefinitionId(rdid)
		if err != nil {
			return nil, err
		}
		normalized[i] = nrdid
	}
	return normalized, nil
}

func (pd *PolicyDefinition) AssignPermissionsParameterNames() ([]string, error) {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return nil, errors.New("PolicyDefinition.AssignPermissionsParameterNames: policy definition is nil, missing properties or parameters")
	}
	names := make([]string, 0)
	for name, param := range pd.Properties.Parameters {
		if param.Metadata == nil || param.Metadata.AssignPermissions == nil || !*param.Metadata.AssignPermissions {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

func (pd *PolicyDefinition) ParameterIsOptional(name string) (bool, error) {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return false, errors.New("PolicyDefinition.ParameterIsOptional: policy definition is nil, missing properties or parameters")
	}
	param, ok := pd.Properties.Parameters[name]
	if !ok {
		return false, fmt.Errorf("PolicyDefinition.ParameterIsOptional: parameter %s not found in policy definition", name)
	}
	if param.DefaultValue == nil {
		return false, nil
	}
	return true, nil
}

func (pd *PolicyDefinition) Parameter(name string) *armpolicy.ParameterDefinitionsValue {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return nil
	}
	ret, ok := pd.Properties.Parameters[name]
	if !ok {
		return nil
	}
	return ret
}

// SetAssignPermissionsOnParameter sets the AssignPermissions metadata field to true for the parameter with the given name.
func (pd *PolicyDefinition) SetAssignPermissionsOnParameter(parameterName string) {
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

// UnsetAssignPermissionsOnParameter removes the AssignPermissions metadata field for the parameter with the given name.
func (pd *PolicyDefinition) UnsetAssignPermissionsOnParameter(parameterName string) {
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

// normalizeRoleDefinitionId takes a Azure builtin role definition id and returns a normalized id.
// This is one without the management group portion.
func normalizeRoleDefinitionId(id string) (string, error) {
	resId, err := arm.ParseResourceID(id)
	if err != nil {
		return "", fmt.Errorf("normalizeRoleDefinitionId: could not parse resource id: %w", err)
	}
	return fmt.Sprintf("/providers/Microsoft.Authorization/roleDefinitions/%s", resId.Name), nil
}
