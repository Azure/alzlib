// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
package alzlib

import (
	mapset "github.com/deckarep/golang-set/v2"
)

// Archetype represents an archetype definition that hasn't been assigned to a management group
// The contents of the sets represent the map keys of the corresponding AlzLib maps.
type Archetype struct {
	PolicyDefinitions    mapset.Set[string]
	PolicyAssignments    mapset.Set[string]
	PolicySetDefinitions mapset.Set[string]
	RoleDefinitions      mapset.Set[string]
	name                 string
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
