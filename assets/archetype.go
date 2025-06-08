package assets

import (
	"encoding/json"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
	"gopkg.in/yaml.v3"
)

// Archetype represents an archetype definition that hasn't been assigned to a management group
// The contents of the sets represent the map keys of the corresponding AlzLib maps.
// Do not create this struct directly, use NewArchetype instead.
type Archetype struct {
	PolicyDefinitions    mapset.Set[string]
	PolicyAssignments    mapset.Set[string]
	PolicySetDefinitions mapset.Set[string]
	RoleDefinitions      mapset.Set[string]
	Name                 string
}

type archetype struct {
	PolicyDefinitions    []string `json:"policy_definitions" yaml:"policy_definitions"`
	PolicyAssignments    []string `json:"policy_assignments" yaml:"policy_assignments"`
	PolicySetDefinitions []string `json:"policy_set_definitions" yaml:"policy_set_definitions"`
	RoleDefinitions      []string `json:"role_definitions" yaml:"role_definitions"`
	Name                 string   `json:"name" yaml:"name"`
}

// NewArchetype creates a new Archetype with the given name.
func NewArchetype(name string) *Archetype {
	return &Archetype{
		PolicyDefinitions:    mapset.NewThreadUnsafeSet[string](),
		PolicyAssignments:    mapset.NewThreadUnsafeSet[string](),
		PolicySetDefinitions: mapset.NewThreadUnsafeSet[string](),
		RoleDefinitions:      mapset.NewThreadUnsafeSet[string](),
		Name:                 name,
	}
}

// Copy creates a deep copy of the archetype.
func (a *Archetype) Copy() *Archetype {
	return &Archetype{
		PolicyDefinitions:    a.PolicyDefinitions.Clone(),
		PolicyAssignments:    a.PolicyAssignments.Clone(),
		PolicySetDefinitions: a.PolicySetDefinitions.Clone(),
		RoleDefinitions:      a.RoleDefinitions.Clone(),
		Name:                 a.Name,
	}
}

// MarshalJSON creates a JSON representation of the Archetype.
func (a *Archetype) MarshalJSON() ([]byte, error) {
	tmp := archetype{
		Name:                 a.Name,
		PolicyAssignments:    mapset.Sorted(a.PolicyAssignments),
		PolicyDefinitions:    mapset.Sorted(a.PolicyDefinitions),
		PolicySetDefinitions: mapset.Sorted(a.PolicySetDefinitions),
		RoleDefinitions:      mapset.Sorted(a.RoleDefinitions),
	}
	data, err := json.Marshal(tmp)
	if err != nil {
		return nil, fmt.Errorf("Archetype.MarshalJSON: json.Marshal error: %w", err)
	}
	return data, nil
}

// UnmarshalJSON creates a Archetype from the supplied JSON bytes.
func (a *Archetype) UnmarshalJSON(data []byte) error {
	tmp := archetype{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("Archetype.UnmarshalJSON: json.Unmarshal error: %w", err)
	}
	a.Name = tmp.Name
	a.PolicyAssignments = mapset.NewSet[string](tmp.PolicyAssignments...)
	a.PolicyDefinitions = mapset.NewSet[string](tmp.PolicyDefinitions...)
	a.PolicySetDefinitions = mapset.NewSet[string](tmp.PolicySetDefinitions...)
	a.RoleDefinitions = mapset.NewSet[string](tmp.RoleDefinitions...)
	return nil
}

// UnmarshalYAML creates a Archetype from the supplied YAML node.
func (a *Archetype) UnmarshalYAML(n *yaml.Node) error {
	tmp := archetype{}
	if err := n.Decode(&tmp); err != nil {
		return fmt.Errorf("Archetype.UnmarshalYAML: yaml.Node.Decode error: %w", err)
	}
	a.Name = tmp.Name
	a.PolicyAssignments = mapset.NewSet[string](tmp.PolicyAssignments...)
	a.PolicyDefinitions = mapset.NewSet[string](tmp.PolicyDefinitions...)
	a.PolicySetDefinitions = mapset.NewSet[string](tmp.PolicySetDefinitions...)
	a.RoleDefinitions = mapset.NewSet[string](tmp.RoleDefinitions...)
	return nil
}
