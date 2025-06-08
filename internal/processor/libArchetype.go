// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"encoding/json"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
	"gopkg.in/yaml.v3"
)

// LibArchetype represents an archetype definition file,
// it used to construct the Archetype struct and is then added to the AlzLib struct.
type LibArchetype struct {
	Name                 string             `json:"name" yaml:"name"`
	PolicyAssignments    mapset.Set[string] `json:"policy_assignments" yaml:"policy_assignments"`
	PolicyDefinitions    mapset.Set[string] `json:"policy_definitions" yaml:"policy_definitions"`
	PolicySetDefinitions mapset.Set[string] `json:"policy_set_definitions" yaml:"policy_set_definitions"`
	RoleDefinitions      mapset.Set[string] `json:"role_definitions" yaml:"role_definitions"`
}

// libArchetype is a struct used to marshal/unmarshal the JSON or YAML representation of an archetype.
type libArchetype struct {
	Name                 string   `json:"name" yaml:"name"`
	PolicyAssignments    []string `json:"policy_assignments" yaml:"policy_assignments"`
	PolicyDefinitions    []string `json:"policy_definitions" yaml:"policy_definitions"`
	PolicySetDefinitions []string `json:"policy_set_definitions" yaml:"policy_set_definitions"`
	RoleDefinitions      []string `json:"role_definitions" yaml:"role_definitions"`
}

// MarshalJSON creates a JSON representation of the LibArchetype.
func (la *LibArchetype) MarshalJSON() ([]byte, error) {
	tmp := libArchetype{
		Name:                 la.Name,
		PolicyAssignments:    mapset.Sorted(la.PolicyAssignments),
		PolicyDefinitions:    mapset.Sorted(la.PolicyDefinitions),
		PolicySetDefinitions: mapset.Sorted(la.PolicySetDefinitions),
		RoleDefinitions:      mapset.Sorted(la.RoleDefinitions),
	}
	data, err := json.Marshal(tmp)
	if err != nil {
		return nil, fmt.Errorf("LibArchetype.MarshalJSON: json.Marshal error: %w", err)
	}
	return data, nil
}

// UnmarshalJSON creates a LibArchetype from the supplied JSON bytes.
func (la *LibArchetype) UnmarshalJSON(data []byte) error {
	tmp := libArchetype{}
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

// UnmarshalYAML creates a LibArchetype from the supplied JSON bytes.
func (la *LibArchetype) UnmarshalYAML(n *yaml.Node) error {
	tmp := libArchetype{}
	if err := n.Decode(&tmp); err != nil {
		return fmt.Errorf("LibArchetype.UnmarshalYAML: yaml.Node.Decode error: %w", err)
	}
	la.Name = tmp.Name
	la.PolicyAssignments = mapset.NewSet[string](tmp.PolicyAssignments...)
	la.PolicyDefinitions = mapset.NewSet[string](tmp.PolicyDefinitions...)
	la.PolicySetDefinitions = mapset.NewSet[string](tmp.PolicySetDefinitions...)
	la.RoleDefinitions = mapset.NewSet[string](tmp.RoleDefinitions...)
	return nil
}
