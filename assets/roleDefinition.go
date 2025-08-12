// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

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
