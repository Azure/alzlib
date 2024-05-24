// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/to"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
)

const (
	ManagementGroupIdFmt     = "/providers/Microsoft.Management/managementGroups/%s"
	PolicyAssignmentIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyAssignments/%s"
	PolicyDefinitionIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyDefinitions/%s"
	PolicySetDefinitionIdFmt = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policySetDefinitions/%s"
	RoleDefinitionIdFmt      = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/roleDefinitions/%s"
)

// Hierarchy represents a deployment of Azure management group hierarchy.go
type Hierarchy struct {
	mgs    map[string]*ManagementGroup
	alzlib *alzlib.AlzLib
	mu     *sync.RWMutex
}

func NewHierarchy(alzlib *alzlib.AlzLib) *Hierarchy {
	return &Hierarchy{
		mgs:    make(map[string]*ManagementGroup),
		alzlib: alzlib,
		mu:     new(sync.RWMutex),
	}
}

// GetManagementGroup returns the management group with the given name.
func (d *Hierarchy) GetManagementGroup(name string) *ManagementGroup {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if mg, ok := d.mgs[name]; ok {
		return mg
	}
	return nil
}

// ListManagementGroups returns the management group names as a slice of string.
func (d *Hierarchy) ListManagementGroups() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	res := make([]string, len(d.mgs))
	i := 0
	for mgname := range d.mgs {
		res[i] = mgname
		i++
	}
	return res
}

// AddManagementGroup adds a management group to the hierarchy, with a parent if specified.
// If the parent is not specified, the management group is considered the root of the hierarchy.
// The archetype should have been obtained using the `AlzLib.CopyArchetype` method.
// This allows for customization and ensures the correct policy assignment values have been set.
func (h *Hierarchy) AddManagementGroup(ctx context.Context, req ManagementGroupAddRequest) (*ManagementGroup, error) {
	if _, exists := h.mgs[req.Id]; exists {
		return nil, fmt.Errorf("Hierarchy.AddManagementGroup: management group %s already exists", req.Id)
	}
	mg := newManagementGroup()

	mg.name = req.Id
	mg.displayName = req.DisplayName
	mg.children = mapset.NewSet[*ManagementGroup]()
	mg.location = req.Location
	if req.ParentIsExternal {
		if _, ok := h.mgs[req.ParentId]; ok {

			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: external parent management group set, but already exists %s", req.ParentId)
		}
		mg.parentExternal = to.Ptr[string](req.ParentId)
	}
	if !req.ParentIsExternal && req.ParentId != "" {
		parentMg, ok := h.mgs[req.ParentId]
		if !ok {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: parent management group not found %s", req.ParentId)
		}
		mg.parent = parentMg
		h.mgs[req.ParentId].children.Add(mg)
	}

	// We only allow one intermediate root management group, so check if this is the first one.
	if req.ParentIsExternal {
		for mgname, mg := range h.mgs {
			if mg.parentExternal != nil {
				return nil, fmt.Errorf("Hierarchy.AddManagementGroup: multiple root management groups: %s and %s", mgname, req.Id)
			}
		}
	}

	// Get the policy definitions and policy set definitions referenced by the policy assignments.
	assignedPolicyDefinitionIds := mapset.NewThreadUnsafeSet[string]()
	for pa := range req.Archetype.PolicyAssignments.Iter() {
		polAssign, err := h.alzlib.GetPolicyAssignment(pa)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: policy assignment `%s` referenced in management group `%s` does not exist in the library", pa, req.Id)
		}
		referencedResourceId, err := polAssign.ReferencedPolicyDefinitionResourceId()
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: error getting referenced policy definition resource ID for policy assignment `%s` in management group `%s`: %w", pa, req.Id, err)
		}
		assignedPolicyDefinitionIds.Add(referencedResourceId.String())
	}

	if err := h.alzlib.GetDefinitionsFromAzure(ctx, assignedPolicyDefinitionIds.ToSlice()); err != nil {
		return nil, fmt.Errorf("Hierarchy.AddManagementGroup: adding mg `%s` error getting policy definitions from Azure: %w", req.Id, err)
	}

	// make copies of the archetype resources for modification in the Deployment management group.
	for name := range req.Archetype.PolicyDefinitions.Iter() {
		newDef, err := h.alzlib.GetPolicyDefinition(name)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: policy definition `%s` in management group `%s` does not exist in the library", name, req.Id)
		}
		mg.policyDefinitions[name] = newDef
	}
	for name := range req.Archetype.PolicySetDefinitions.Iter() {
		newSetDef, err := h.alzlib.GetPolicySetDefinition(name)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup(): policy set definition `%s` in management group `%s` does not exist in the library", name, req.Id)
		}
		mg.policySetDefinitions[name] = newSetDef
	}
	for name := range req.Archetype.PolicyAssignments.Iter() {
		newpolassign, err := h.alzlib.GetPolicyAssignment(name)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup(): policy assignment `%s` in management group `%s` does not exist in the library", name, req.Id)
		}
		mg.policyAssignments[name] = newpolassign
	}
	for name := range req.Archetype.RoleDefinitions.Iter() {
		newroledef, err := h.alzlib.GetRoleDefinition(name)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup(): role definition `%s` in management group `%s` does not exist in the library", name, req.Id)
		}
		mg.roleDefinitions[name] = newroledef
	}

	// set the hierarchy on the management group.
	mg.hierarchy = h

	// add the management group to the deployment.
	h.mgs[req.Id] = mg

	// run Update to change all refs, etc.
	if err := h.mgs[req.Id].update(nil); err != nil {
		return nil, fmt.Errorf("Hierarchy.AddManagementGroup: adding `%s` error updating assets at scope %w", req.Id, err)
	}

	return mg, nil
}

// policyDefinitionToMg returns a map of policy definition names to the deployed management group name.
func (d *Hierarchy) policyDefinitionToMg() map[string]string {
	res := make(map[string]string, 0)
	for mgname, mg := range d.mgs {
		for pdname := range mg.policyDefinitions {
			res[pdname] = mgname
		}
	}
	return res
}

// policyDefinitionToMg returns a map of policy set definition names to the deployed management group name.
func (d *Hierarchy) policySetDefinitionToMg() map[string]string {
	res := make(map[string]string, 0)
	for mgname, mg := range d.mgs {
		for psdname := range mg.policySetDefinitions {
			res[psdname] = mgname
		}
	}
	return res
}

func uuidV5(s ...string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(strings.Join(s, "")))
}
