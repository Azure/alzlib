// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

// NewRoleDefinition creates a new RoleDefinition from an armauthorization.RoleDefinition.
func NewRoleDefinition(rd armauthorization.RoleDefinition) *RoleDefinition {
	return &RoleDefinition{rd}
}

// RoleDefinition is a wrapper around armauthorization.RoleDefinition to provide additional
// methods or properties if needed.
type RoleDefinition struct {
	armauthorization.RoleDefinition
}
