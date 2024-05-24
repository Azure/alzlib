// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"encoding/json"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
)

// LibArchetype represents an archetype definition file,
// it used to construct the Archetype struct and is then added to the AlzLib struct.
type LibArchetype struct {
	Name                 string             `json:"name"`
	PolicyAssignments    mapset.Set[string] `json:"policy_assignments"`
	PolicyDefinitions    mapset.Set[string] `json:"policy_definitions"`
	PolicySetDefinitions mapset.Set[string] `json:"policy_set_definitions"`
	RoleDefinitions      mapset.Set[string] `json:"role_definitions"`
}

// UnmarshalJSON creates a LibArchetype from the supplied JSON bytes.
func (la *LibArchetype) UnmarshalJSON(data []byte) error {
	tmp := struct {
		Name                 string   `json:"name"`
		PolicyAssignments    []string `json:"policy_assignments"`
		PolicyDefinitions    []string `json:"policy_definitions"`
		PolicySetDefinitions []string `json:"policy_set_definitions"`
		RoleDefinitions      []string `json:"role_definitions"`
	}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("LibArchetype.UnmarshalJSON: json.Unmarshal error: %w", err)
	}
	la.Name = tmp.Name
	la.PolicyAssignments = mapset.NewSet[string](tmp.PolicyAssignments...)
	la.PolicyDefinitions = mapset.NewSet[string](tmp.PolicyDefinitions...)
	la.PolicySetDefinitions = mapset.NewSet[string](tmp.PolicySetDefinitions...)
	la.RoleDefinitions = mapset.NewSet[string](tmp.RoleDefinitions...)
	return nil
}
