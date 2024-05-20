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
	managementGroupIdFmt     = "/providers/Microsoft.Management/managementGroups/%s"
	policyAssignmentIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyAssignments/%s"
	policyDefinitionIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyDefinitions/%s"
	policySetDefinitionIdFmt = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policySetDefinitions/%s"
	roleDefinitionIdFmt      = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/roleDefinitions/%s"
)

// Hierarchy represents a deployment of Azure management group hierarchy
type Hierarchy struct {
	mgs    map[string]*ManagementGroup
	alzlib *alzlib.AlzLib
	mu     *sync.RWMutex
}

type ManagementGroupAddRequest struct {
	Id               string
	DisplayName      string
	ParentId         string
	ParentIsExternal bool
	Archetype        *alzlib.Archetype
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
func (h *Hierarchy) AddManagementGroup(ctx context.Context, req *ManagementGroupAddRequest) error {
	if _, exists := h.mgs[req.Id]; exists {
		return fmt.Errorf("management group %s already exists", req.Id)
	}
	alzmg := newManagementGroup()

	alzmg.name = req.Id
	alzmg.displayName = req.DisplayName
	alzmg.children = mapset.NewSet[*ManagementGroup]()
	if req.ParentIsExternal {
		if _, ok := h.mgs[req.ParentId]; ok {

			return fmt.Errorf("external parent management group set, but already exists %s", req.ParentId)
		}
		alzmg.parentExternal = to.Ptr[string](req.ParentId)
	}
	if !req.ParentIsExternal && req.ParentId != "" {
		mg, ok := h.mgs[req.ParentId]
		if !ok {
			return fmt.Errorf("parent management group not found %s", req.ParentId)
		}
		alzmg.parent = mg
		h.mgs[req.ParentId].children.Add(alzmg)
	}

	// We only allow one intermediate root management group, so check if this is the first one.
	if req.ParentIsExternal {
		for mgname, mg := range h.mgs {
			if mg.parentExternal != nil {
				return fmt.Errorf("multiple root management groups: %s and %s", mgname, req.Id)
			}
		}
	}

	// Get the policy definitions and policy set definitions referenced by the policy assignments.
	assignedPolicyDefinitionIds := mapset.NewThreadUnsafeSet[string]()
	for pa := range req.Archetype.PolicyAssignments.Iter() {
		polAssign, err := h.alzlib.GetPolicyAssignment(pa)
		if err != nil {
			return fmt.Errorf("policy assignment %s referenced in archetype %s does not exist in the library", pa, req.Archetype.name)
		}
		referencedResourceId, err := polAssign.ReferencedPolicyDefinitionResourceId()
		if err != nil {
			return err
		}
		assignedPolicyDefinitionIds.Add(referencedResourceId.String())
	}

	if err := h.alzlib.GetDefinitionsFromAzure(ctx, assignedPolicyDefinitionIds.ToSlice()); err != nil {
		return err
	}

	// make copies of the archetype resources for modification in the Deployment management group.
	for name := range req.Archetype.PolicyDefinitions.Iter() {
		newDef, err := h.alzlib.GetPolicyDefinition(name)
		if err != nil {
			return err
		}
		alzmg.policyDefinitions[name] = newDef
	}
	for name := range req.Archetype.PolicySetDefinitions.Iter() {
		newSetDef, err := h.alzlib.GetPolicySetDefinition(name)
		if err != nil {
			return err
		}
		alzmg.policySetDefinitions[name] = newSetDef
	}
	for name := range req.Archetype.PolicyAssignments.Iter() {
		newpolassign, err := h.alzlib.GetPolicyAssignment(name)
		if err != nil {
			return err
		}
		alzmg.policyAssignments[name] = newpolassign
	}
	for name := range req.Archetype.RoleDefinitions.Iter() {
		newroledef, err := h.alzlib.GetRoleDefinition(name)
		if err != nil {
			return err
		}
		alzmg.roleDefinitions[name] = newroledef
	}

	// add the management group to the deployment.
	h.mgs[req.Id] = alzmg

	// run Update to change all refs, etc.
	if err := h.mgs[req.Id].update(nil); err != nil {
		return err
	}

	return nil
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
