package processor

import (
	"encoding/json"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
)

// LibArchitecture represents a management group hierarchy in the library.
type LibArchitecture struct {
	Name             string                           `json:"name"`
	ManagementGroups []LibArchitectureManagementGroup `json:"management_groups"`
}

// LibArchitectureManagementGroup represents a management group in the library.
type LibArchitectureManagementGroup struct {
	Id          string             `json:"id"`
	DisplayName string             `json:"display_name"`
	Archetypes  mapset.Set[string] `json:"archetypes"`
	ParentId    *string            `json:"parent_id"`
	Exists      bool               `json:"exists"`
}

// UnmarshalJSON creates a LibArchitecture from the supplied JSON bytes.
func (la *LibArchitecture) UnmarshalJSON(data []byte) error {
	tmp := struct {
		Name             string `json:"name"`
		ManagementGroups []struct {
			Id          string   `json:"id"`
			DisplayName string   `json:"display_name"`
			Archetypes  []string `json:"archetypes"`
			ParentId    *string  `json:"parent_id"`
			Exists      bool     `json:"exists"`
		} `json:"management_groups"`
	}{}
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
