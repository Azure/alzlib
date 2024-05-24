// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"encoding/json"
	"errors"
	"fmt"

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

// GetRoleDefinitionResourceIds returns the role definition ids referenced in a policy definition
// if they exist.
// We marshall the policyRule as JSON and then unmarshal into a custom type.
func (pd *PolicyDefinition) GetRoleDefinitionResourceIds() ([]string, error) {
	if pd == nil || pd.Properties == nil || pd.Properties.PolicyRule == nil {
		return nil, errors.New("policy definition is nil, missing properties or policy rule")
	}
	j, err := json.Marshal(pd.Properties.PolicyRule)
	if err != nil {
		return nil, fmt.Errorf("could not marshall policy rule: %w", err)
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
		return nil, fmt.Errorf("could not unmarshall policy rule: %w", err)
	}
	if r.Then.Details == nil || r.Then.Details.RoleDefinitionIds == nil || len(r.Then.Details.RoleDefinitionIds) == 0 {
		return []string{}, nil
	}
	return r.Then.Details.RoleDefinitionIds, nil
}

func (pd *PolicyDefinition) GetNormalizedRoleDefinitionResourceIds() ([]string, error) {
	rdids, err := pd.GetRoleDefinitionResourceIds()
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

func (pd *PolicyDefinition) GetAssignPermissionsParameterNames() ([]string, error) {
	if pd == nil || pd.Properties == nil || pd.Properties.Parameters == nil {
		return nil, errors.New("policy definition is nil, missing properties or parameters")
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

// normalizeRoleDefinitionId takes a Azure builtin role definition id and returns a normalized id.
// This is one without the management group portion.
func normalizeRoleDefinitionId(id string) (string, error) {
	resId, err := arm.ParseResourceID(id)
	if err != nil {
		return "", fmt.Errorf("could not parse resource id: %w", err)
	}
	return fmt.Sprintf("/providers/Microsoft.Authorization/roleDefinitions/%s", resId.Name), nil
}
