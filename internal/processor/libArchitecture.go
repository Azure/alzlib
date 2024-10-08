// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"encoding/json"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
	"gopkg.in/yaml.v3"
)

// LibArchitecture represents a management group hierarchy in the library.
type LibArchitecture struct {
	Name             string                           `json:"name" yaml:"name"`
	ManagementGroups []LibArchitectureManagementGroup `json:"management_groups" yaml:"management_groups"`
}

// LibArchitectureManagementGroup represents a management group in the library.
type LibArchitectureManagementGroup struct {
	Id          string             `json:"id" yaml:"id"`
	DisplayName string             `json:"display_name" yaml:"display_name"`
	Archetypes  mapset.Set[string] `json:"archetypes" yaml:"archetypes"`
	ParentId    *string            `json:"parent_id" yaml:"parent_id"`
	Exists      bool               `json:"exists" yaml:"exists"`
}

type libArchitectureUnmarshaler struct {
	Name             string `json:"name" yaml:"name"`
	ManagementGroups []struct {
		Id          string   `json:"id" yaml:"id"`
		DisplayName string   `json:"display_name" yaml:"display_name"`
		Archetypes  []string `json:"archetypes" yaml:"archetypes"`
		ParentId    *string  `json:"parent_id" yaml:"parent_id"`
		Exists      bool     `json:"exists" yaml:"exists"`
	} `json:"management_groups" yaml:"management_groups"`
}

// UnmarshalJSON creates a LibArchitecture from the supplied JSON bytes.
func (la *LibArchitecture) UnmarshalJSON(data []byte) error {
	tmp := libArchitectureUnmarshaler{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("LibArchitecture.UnmarshalJSON: json.Unmarshal error: %w", err)
	}
	la.Name = tmp.Name
	la.ManagementGroups = make([]LibArchitectureManagementGroup, len(tmp.ManagementGroups))
	for i, mg := range tmp.ManagementGroups {
		la.ManagementGroups[i].Id = mg.Id
		la.ManagementGroups[i].DisplayName = mg.DisplayName
		la.ManagementGroups[i].Archetypes = mapset.NewSet[string](mg.Archetypes...)
		la.ManagementGroups[i].ParentId = mg.ParentId
		la.ManagementGroups[i].Exists = mg.Exists
	}
	return nil
}

// UnmarshalJSON creates a LibArchitecture from the supplied JSON bytes.
func (la *LibArchitecture) UnmarshalYAML(n *yaml.Node) error {
	tmp := libArchitectureUnmarshaler{}
	if err := n.Decode(&tmp); err != nil {
		return fmt.Errorf("LibArchitecture.UnmarshalYAML: yaml.Node.Decode error: %w", err)
	}
	la.Name = tmp.Name
	la.ManagementGroups = make([]LibArchitectureManagementGroup, len(tmp.ManagementGroups))
	for i, mg := range tmp.ManagementGroups {
		la.ManagementGroups[i].Id = mg.Id
		la.ManagementGroups[i].DisplayName = mg.DisplayName
		la.ManagementGroups[i].Archetypes = mapset.NewSet[string](mg.Archetypes...)
		la.ManagementGroups[i].ParentId = mg.ParentId
		la.ManagementGroups[i].Exists = mg.Exists
	}
	return nil
}
