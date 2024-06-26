// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
package alzlib

import (
	mapset "github.com/deckarep/golang-set/v2"
)

// Archetype represents the exported archetype definition that hasn't been assigned to a management group
// The contents of the sets represent the map keys of the corresponding AlzLib maps.
type Archetype struct {
	PolicyDefinitions    mapset.Set[string]
	PolicyAssignments    mapset.Set[string]
	PolicySetDefinitions mapset.Set[string]
	RoleDefinitions      mapset.Set[string]
	name                 string
}

// archetype represents an archetype definition that hasn't been assigned to a management group
// The contents of the sets represent the map keys of the corresponding AlzLib maps.
type archetype struct {
	policyDefinitions    mapset.Set[string]
	policyAssignments    mapset.Set[string]
	policySetDefinitions mapset.Set[string]
	roleDefinitions      mapset.Set[string]
	name                 string
}

func newArchitype(name string) *archetype {
	return &archetype{
		policyDefinitions:    mapset.NewThreadUnsafeSet[string](),
		policyAssignments:    mapset.NewThreadUnsafeSet[string](),
		policySetDefinitions: mapset.NewThreadUnsafeSet[string](),
		roleDefinitions:      mapset.NewThreadUnsafeSet[string](),
		name:                 name,
	}
}

func NewArchetype(name string) *Archetype {
	return &Archetype{
		PolicyDefinitions:    mapset.NewThreadUnsafeSet[string](),
		PolicyAssignments:    mapset.NewThreadUnsafeSet[string](),
		PolicySetDefinitions: mapset.NewThreadUnsafeSet[string](),
		RoleDefinitions:      mapset.NewThreadUnsafeSet[string](),
		name:                 name,
	}
}

func (a *Archetype) Name() string {
	return a.name
}

// copy creates a deep copy of the archetype.
func (a *archetype) copy() *Archetype {
	return &Archetype{
		PolicyDefinitions:    a.policyDefinitions.Clone(),
		PolicyAssignments:    a.policyAssignments.Clone(),
		PolicySetDefinitions: a.policySetDefinitions.Clone(),
		RoleDefinitions:      a.roleDefinitions.Clone(),
		name:                 a.name,
	}
}
