// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"encoding/json"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
)

// LibArchetypeOverride represents an archetype override definition file,
// it used to construct generate a new Archetype struct from an existing
// full archetype and is then added to the AlzLib struct.
type LibArchetypeOverride struct {
	Name                         string             `json:"name"`
	BaseArchetype                string             `json:"base_archetype"`
	PolicyAssignmentsToAdd       mapset.Set[string] `json:"policy_assignments_to_add"`
	PolicyAssignmentsToRemove    mapset.Set[string] `json:"policy_assignments_to_remove"`
	PolicyDefinitionsToAdd       mapset.Set[string] `json:"policy_definitions_to_add"`
	PolicyDefinitionsToRemove    mapset.Set[string] `json:"policy_definitions_to_remove"`
	PolicySetDefinitionsToAdd    mapset.Set[string] `json:"policy_set_definitions_to_add"`
	PolicySetDefinitionsToRemove mapset.Set[string] `json:"policy_set_definitions_to_remove"`
	RoleDefinitionsToAdd         mapset.Set[string] `json:"role_definitions_to_add"`
	RoleDefinitionsToRemove      mapset.Set[string] `json:"role_definitions_to_remove"`
}

func (lao *LibArchetypeOverride) UnmarshalJSON(data []byte) error {
	tmp := struct {
		Name                         string   `json:"name"`
		BaseArchetype                string   `json:"base_archetype"`
		PolicyAssignmentsToAdd       []string `json:"policy_assignments_to_add"`
		PolicyAssignmentsToRemove    []string `json:"policy_assignments_to_remove"`
		PolicyDefinitionsToAdd       []string `json:"policy_definitions_to_add"`
		PolicyDefinitionsToRemove    []string `json:"policy_definitions_to_remove"`
		PolicySetDefinitionsToAdd    []string `json:"policy_set_definitions_to_add"`
		PolicySetDefinitionsToRemove []string `json:"policy_set_definitions_to_remove"`
		RoleDefinitionsToAdd         []string `json:"role_definitions_to_add"`
		RoleDefinitionsToRemove      []string `json:"role_definitions_to_remove"`
	}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("LibArchetypeOverride.UnmarshalJSON: json.Unmarshal error: %w", err)
	}
	lao.Name = tmp.Name
	lao.BaseArchetype = tmp.BaseArchetype
	lao.PolicyAssignmentsToAdd = mapset.NewThreadUnsafeSet[string](tmp.PolicyAssignmentsToAdd...)
	lao.PolicyAssignmentsToRemove = mapset.NewThreadUnsafeSet[string](tmp.PolicyAssignmentsToRemove...)
	lao.PolicyDefinitionsToAdd = mapset.NewThreadUnsafeSet[string](tmp.PolicyDefinitionsToAdd...)
	lao.PolicyDefinitionsToRemove = mapset.NewThreadUnsafeSet[string](tmp.PolicyDefinitionsToRemove...)
	lao.PolicySetDefinitionsToAdd = mapset.NewThreadUnsafeSet[string](tmp.PolicySetDefinitionsToAdd...)
	lao.PolicySetDefinitionsToRemove = mapset.NewThreadUnsafeSet[string](tmp.PolicySetDefinitionsToRemove...)
	lao.RoleDefinitionsToAdd = mapset.NewThreadUnsafeSet[string](tmp.RoleDefinitionsToAdd...)
	lao.RoleDefinitionsToRemove = mapset.NewThreadUnsafeSet[string](tmp.RoleDefinitionsToRemove...)
	return nil
}
