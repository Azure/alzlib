// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"encoding/json"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

// NewRoleDefinition creates a new RoleDefinition from an armauthorization.RoleDefinition.
func NewRoleDefinition(rd armauthorization.RoleDefinition) *RoleDefinition {
	return &RoleDefinition{rd}
}

// NewRoleDefinitionValidate creates a new RoleDefinition instance and validates it.
func NewRoleDefinitionValidate(rd armauthorization.RoleDefinition) (*RoleDefinition, error) {
	rdObj := NewRoleDefinition(rd)

	if err := ValidateRoleDefinition(rdObj); err != nil {
		return nil, err
	}

	return rdObj, nil
}

// RoleDefinition is a wrapper around armauthorization.RoleDefinition to provide additional
// methods or properties if needed.
type RoleDefinition struct {
	armauthorization.RoleDefinition
}

// ValidateRoleDefinition checks if the RoleDefinition is valid.
func ValidateRoleDefinition(rd *RoleDefinition) error {
	if rd == nil {
		return NewErrPropertyMustNotBeNil("RoleDefinition")
	}

	if rd.Name == nil {
		return NewErrPropertyMustNotBeNil("name")
	}

	if rd.Properties.RoleName == nil {
		return NewErrPropertyMustNotBeNil("properties.roleName")
	}

	if rd.Properties.Permissions == nil {
		return NewErrPropertyMustNotBeNil("properties.permissions")
	}

	if rd.Properties.AssignableScopes == nil {
		rd.Properties.AssignableScopes = make([]*string, 0)
	}

	return nil
}

// UnmarshalJSON customizes the JSON unmarshaling for RoleDefinition.
func (rd *RoleDefinition) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &rd.RoleDefinition); err != nil {
		return err
	}

	return ValidateRoleDefinition(rd)
}
