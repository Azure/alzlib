package assets

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"

func NewRoleDefinition(rd armauthorization.RoleDefinition) *RoleDefinition {
	return &RoleDefinition{rd}
}

type RoleDefinition struct {
	armauthorization.RoleDefinition
}
