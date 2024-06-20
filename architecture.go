package alzlib

import (
	"fmt"

	"github.com/Azure/alzlib/processor"
	mapset "github.com/deckarep/golang-set/v2"
)

type Architecture struct {
	name   string
	mgs    map[string]*ArchitectureManagementGroup
	alzlib *AlzLib
}

func NewArchitecture(name string, az *AlzLib) *Architecture {
	return &Architecture{
		name:   name,
		mgs:    make(map[string]*ArchitectureManagementGroup),
		alzlib: az,
	}
}

func (a *Architecture) RootMgs() (res []*ArchitectureManagementGroup) {
	for _, mg := range a.mgs {
		if mg.parent != nil {
			continue
		}
		res = append(res, mg)
	}
	return res
}

type ArchitectureManagementGroup struct {
	id           string
	displayName  string
	children     mapset.Set[*ArchitectureManagementGroup]
	parent       *ArchitectureManagementGroup
	exists       bool
	archetypes   mapset.Set[*archetype]
	architecture *Architecture
}

func newArchitectureManagementGroup(id, displayName string, exists bool, arch *Architecture) *ArchitectureManagementGroup {
	return &ArchitectureManagementGroup{
		id:           id,
		displayName:  displayName,
		children:     mapset.NewThreadUnsafeSet[*ArchitectureManagementGroup](),
		exists:       exists,
		archetypes:   mapset.NewThreadUnsafeSet[*archetype](),
		architecture: arch,
	}
}

func (mg *ArchitectureManagementGroup) Archetypes() (res []*Archetype) {
	for arch := range mg.archetypes.Iter() {
		res = append(res, arch.copy())
	}
	return res
}

func (mg *ArchitectureManagementGroup) Children() (res []*ArchitectureManagementGroup) {
	for child := range mg.children.Iter() {
		res = append(res, child)
	}
	return res
}

func (mg *ArchitectureManagementGroup) DisplayName() string {
	return mg.displayName
}

func (mg *ArchitectureManagementGroup) Id() string {
	return mg.id
}

func (a *Architecture) addMgFromProcessor(libMg processor.LibArchitectureManagementGroup, az *AlzLib) error {
	if _, ok := a.mgs[libMg.Id]; ok {
		return fmt.Errorf("Architecture.addMg: management group %s already exists", libMg.Id)
	}
	mg := newArchitectureManagementGroup(libMg.Id, libMg.DisplayName, libMg.Exists, a)
	// check parent exists and create parent-child relationship
	if libMg.ParentId != nil {
		parent, ok := a.mgs[*libMg.ParentId]
		if !ok {
			return fmt.Errorf("Architecture.addMg: parent management group does not exist %s", *libMg.ParentId)
		}
		mg.parent = parent
		mg.parent.children.Add(mg)
	}
	mg.archetypes = mapset.NewThreadUnsafeSet[*archetype]()
	for archName := range libMg.Archetypes.Iter() {
		arch, ok := az.archetypes[archName]
		if !ok {
			return fmt.Errorf("Architecture.addMg: archetype not found adding archetype `%s` to management group `%s`", archName, libMg.Id)
		}
		mg.archetypes.Add(arch)
	}
	a.mgs[mg.id] = mg
	return nil
}
