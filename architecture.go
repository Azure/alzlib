// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"fmt"
	"slices"

	"github.com/Azure/alzlib/internal/processor"
	mapset "github.com/deckarep/golang-set/v2"
)

// Architecture represents an Azure architecture that has not been deployed.
// Do not create this struct directly, use NewArchitecture instead.
type Architecture struct {
	name   string
	mgs    map[string]*ArchitectureManagementGroup
	alzlib *AlzLib
}

// NewArchitecture creates a new Architecture with the given name and AlzLib.
func NewArchitecture(name string, az *AlzLib) *Architecture {
	return &Architecture{
		name:   name,
		mgs:    make(map[string]*ArchitectureManagementGroup),
		alzlib: az,
	}
}

// Name returns the name of the architecture.
func (a *Architecture) Name() string {
	return a.name
}

// RootMgs returns the top level management groups of the architecture.
func (a *Architecture) RootMgs() (res []*ArchitectureManagementGroup) {
	for _, mg := range a.mgs {
		if mg.parent != nil {
			continue
		}
		res = append(res, mg)
	}
	slices.SortFunc(res, func(a, b *ArchitectureManagementGroup) int {
		if a.id < b.id {
			return -1
		}
		if a.id > b.id {
			return 1
		}
		return 0
	})
	return res
}

// ArchitectureManagementGroup represents a management group in an undeployed architecture.
type ArchitectureManagementGroup struct {
	id           string
	displayName  string
	children     mapset.Set[*ArchitectureManagementGroup]
	parent       *ArchitectureManagementGroup
	exists       bool
	archetypes   mapset.Set[*Archetype]
	architecture *Architecture
}

func newArchitectureManagementGroup(id, displayName string, exists bool, arch *Architecture) *ArchitectureManagementGroup {
	return &ArchitectureManagementGroup{
		id:           id,
		displayName:  displayName,
		children:     mapset.NewThreadUnsafeSet[*ArchitectureManagementGroup](),
		exists:       exists,
		archetypes:   mapset.NewThreadUnsafeSet[*Archetype](),
		architecture: arch,
	}
}

// Archetypes returns the archetypes assigned to the management group.
func (mg *ArchitectureManagementGroup) Archetypes() (res []*Archetype) {
	for arch := range mg.archetypes.Iter() {
		res = append(res, arch.copy())
	}
	return res
}

// Children returns the child management groups of the management group.
func (mg *ArchitectureManagementGroup) Children() (res []*ArchitectureManagementGroup) {
	for child := range mg.children.Iter() {
		res = append(res, child)
	}
	return res
}

// DisplayName returns the display name of the management group.
func (mg *ArchitectureManagementGroup) DisplayName() string {
	return mg.displayName
}

// Id returns the id of the management group.
func (mg *ArchitectureManagementGroup) Id() string {
	return mg.id
}

// Exists returns the exists value.
func (mg *ArchitectureManagementGroup) Exists() bool {
	return mg.exists
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
	mg.archetypes = mapset.NewThreadUnsafeSet[*Archetype]()
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
