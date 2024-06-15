package alzlib

import (
	"fmt"

	"github.com/Azure/alzlib/processor"
)

type Architecture struct {
	name string
	mgs  map[string]*managementGroup
}

func NewArchitecture(name string) *Architecture {
	return &Architecture{
		name: name,
		mgs:  make(map[string]*managementGroup),
	}
}

type managementGroup struct {
	name        string
	displayName string
	children    []*managementGroup
	parent      *managementGroup
	exists      bool
	archetypes  []*Archetype
}

func (a *Architecture) addMg(libMg processor.LibArchitectureManagementGroup) error {
	if _, ok := a.mgs[libMg.Id]; ok {
		return fmt.Errorf("Architecture.addMg: management group %s already exists", libMg.Id)
	}
	mg := new(managementGroup)
	// check parent exists
	if libMg.ParentId != nil {
		parent, ok := a.mgs[*libMg.ParentId]
		if !ok {
			return fmt.Errorf("Architecture.addMg: parent management group does not exist %s", *libMg.ParentId)
		}
		mg.parent = parent
		mg.parent.children = append(mg.parent.children, mg)
	}
	mg.name = libMg.Id
	mg.displayName = libMg.DisplayName
	mg.exists = libMg.Exists
	mg.archetypes = make([]*Archetype, libMg.Archetypes.Cardinality())
	return nil
}
