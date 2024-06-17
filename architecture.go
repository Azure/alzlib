package alzlib

import (
	"fmt"

	"github.com/Azure/alzlib/processor"
	mapset "github.com/deckarep/golang-set/v2"
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
	id          string
	displayName string
	children    mapset.Set[*managementGroup]
	parent      *managementGroup
	exists      bool
	archetypes  mapset.Set[*Archetype]
}

func newManagementGroup(id, displayName string, exists bool) *managementGroup {
	return &managementGroup{
		id:          id,
		displayName: displayName,
		children:    mapset.NewThreadUnsafeSet[*managementGroup](),
		exists:      exists,
		archetypes:  mapset.NewThreadUnsafeSet[*Archetype](),
	}
}

func (a *Architecture) addMgFromProcessor(libMg processor.LibArchitectureManagementGroup, az *AlzLib) error {
	if _, ok := a.mgs[libMg.Id]; ok {
		return fmt.Errorf("Architecture.addMg: management group %s already exists", libMg.Id)
	}
	mg := newManagementGroup(libMg.Id, libMg.DisplayName, libMg.Exists)
	// check parent exists and create parent-child relationship
	if libMg.ParentId != nil {
		parent, ok := a.mgs[*libMg.ParentId]
		if !ok {
			return fmt.Errorf("Architecture.addMg: parent management group does not exist %s", *libMg.ParentId)
		}
		mg.parent = parent
		mg.parent.children.Add(mg)
	}
	mg.archetypes = mapset.NewThreadUnsafeSet[*Archetype]()
	for archName := range libMg.Archetypes.Iter() {
		arch, err := az.CopyArchetype(archName)
		if err != nil {
			return fmt.Errorf("Architecture.addMg: error adding archetype `%s` to management group `%s` %w", archName, libMg.Id, err)
		}
		mg.archetypes.Add(arch)
	}
	a.mgs[mg.id] = mg
	return nil
}
