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

// Hierarchy represents a deployment of Azure management group hierarchy.
type Hierarchy struct {
	mgs    map[string]*HierarchyManagementGroup
	alzlib *alzlib.AlzLib
	mu     *sync.RWMutex
}

func NewHierarchy(alzlib *alzlib.AlzLib) *Hierarchy {
	return &Hierarchy{
		mgs:    make(map[string]*HierarchyManagementGroup),
		alzlib: alzlib,
		mu:     new(sync.RWMutex),
	}
}

// ManagementGroup returns the management group with the given name.
func (h *Hierarchy) ManagementGroup(name string) *HierarchyManagementGroup {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if mg, ok := h.mgs[name]; ok {
		return mg
	}
	return nil
}

// ManagementGroups returns the management group names as a slice of string.
func (h *Hierarchy) ManagementGroups() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	res := make([]string, len(h.mgs))
	i := 0
	for mgname := range h.mgs {
		res[i] = mgname
		i++
	}
	return res
}

func (h *Hierarchy) FromArchitecture(ctx context.Context, arch, externalParentId, location string) error {
	architecture, err := h.alzlib.Architecture(arch)
	if err != nil {
		return fmt.Errorf("Hierarchy.FromArchitecture: error getting architecture `%s`: %w", arch, err)
	}
	// Get the architecture root management groups.
	for _, a := range architecture.RootMgs() {
		if err := recurseAddManagementGroup(ctx, h, a, externalParentId, location, true); err != nil {
			return fmt.Errorf("Hierarchy.FromArchitecture: recursion error on architecture `%s` %w", arch, err)
		}
	}
	return nil
}

func recurseAddManagementGroup(ctx context.Context, h *Hierarchy, archMg *alzlib.ArchitectureManagementGroup, parent, location string, externalParent bool) error {
	req := managementGroupAddRequest{
		id:               archMg.Id(),
		displayName:      archMg.DisplayName(),
		archetypes:       archMg.Archetypes(),
		location:         location,
		parentId:         parent,
		parentIsExternal: externalParent,
	}
	if _, err := h.addManagementGroup(ctx, req); err != nil {
		return fmt.Errorf("Hierarchy.recurseAddManagementGroup: error adding management group `%s`: %w", archMg.Id(), err)
	}
	for _, child := range archMg.Children() {
		if err := recurseAddManagementGroup(ctx, h, child, archMg.Id(), location, false); err != nil {
			return err
		}
	}
	return nil
}

// addManagementGroup adds a management group to the hierarchy, with a parent if specified.
// If the parent is not specified, the management group is considered the root of the hierarchy.
// The archetype should have been obtained using the `AlzLib.CopyArchetype` method.
// This allows for customization and ensures the correct policy assignment values have been set.
func (h *Hierarchy) addManagementGroup(ctx context.Context, req managementGroupAddRequest) (*HierarchyManagementGroup, error) {
	if req.parentId == "" {
		return nil, fmt.Errorf("Hierarchy.AddManagementGroup: parent management group not specified for `%s`", req.id)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.mgs[req.id]; exists {
		return nil, fmt.Errorf("Hierarchy.AddManagementGroup: management group %s already exists", req.id)
	}
	mg := newManagementGroup()

	mg.id = req.id
	mg.displayName = req.displayName
	mg.exists = req.exists
	mg.children = mapset.NewSet[*HierarchyManagementGroup]()
	mg.location = req.location
	if req.parentIsExternal {
		if _, ok := h.mgs[req.parentId]; ok {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: external parent management group set, but already exists %s", req.parentId)
		}
		mg.parentExternal = to.Ptr(req.parentId)
	}
	if !req.parentIsExternal {
		parentMg, ok := h.mgs[req.parentId]
		if !ok {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: parent management group not found %s", req.parentId)
		}
		mg.parent = parentMg
		h.mgs[req.parentId].children.Add(mg)
	}

	// Get the policy definitions and policy set definitions referenced by the policy assignments.
	assignedPolicyDefinitionIds := mapset.NewThreadUnsafeSet[string]()

	// Copmbine all assignments form all supplied archetypes into a single set
	allPolicyAssignments := mapset.NewThreadUnsafeSet[string]()
	for _, archetype := range req.archetypes {
		allPolicyAssignments = allPolicyAssignments.Union(archetype.PolicyAssignments)
	}
	for pa := range allPolicyAssignments.Iter() {
		polAssign, err := h.alzlib.PolicyAssignment(pa)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: policy assignment `%s` referenced in management group `%s` does not exist in the library", pa, req.id)
		}
		referencedResourceId, err := polAssign.ReferencedPolicyDefinitionResourceId()
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: error getting referenced policy definition resource ID for policy assignment `%s` in management group `%s`: %w", pa, req.id, err)
		}
		assignedPolicyDefinitionIds.Add(referencedResourceId.String())
	}

	if err := h.alzlib.GetDefinitionsFromAzure(ctx, assignedPolicyDefinitionIds.ToSlice()); err != nil {
		return nil, fmt.Errorf("Hierarchy.AddManagementGroup: adding mg `%s` error getting policy definitions from Azure: %w", req.id, err)
	}

	// Now that we are sure that we have all the definitions in the library,
	// make copies of the archetype resources for modification in the Deployment management group.

	// Copmbine all policy definitions form all supplied archetypes into a single set
	allPolicyDefinitions := mapset.NewThreadUnsafeSet[string]()
	for _, archetype := range req.archetypes {
		allPolicyDefinitions = allPolicyDefinitions.Union(archetype.PolicyDefinitions)
	}
	for name := range allPolicyDefinitions.Iter() {
		newDef, err := h.alzlib.PolicyDefinition(name)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup: policy definition `%s` in management group `%s` does not exist in the library", name, req.id)
		}
		mg.policyDefinitions[name] = newDef
	}
	// Copmbine all policy set definitions form all supplied archetypes into a single set
	allPolicySetDefinitions := mapset.NewThreadUnsafeSet[string]()
	for _, archetype := range req.archetypes {
		allPolicySetDefinitions = allPolicySetDefinitions.Union(archetype.PolicySetDefinitions)
	}
	for name := range allPolicySetDefinitions.Iter() {
		newSetDef, err := h.alzlib.PolicySetDefinition(name)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup(): policy set definition `%s` in management group `%s` does not exist in the library", name, req.id)
		}
		mg.policySetDefinitions[name] = newSetDef
	}
	// Now that the policy definitions and policy set definitions have been copied, we can add the policy assignments
	for name := range allPolicyAssignments.Iter() {
		newpolassign, err := h.alzlib.PolicyAssignment(name)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup(): policy assignment `%s` in management group `%s` does not exist in the library", name, req.id)
		}
		mg.policyAssignments[name] = newpolassign
	}

	// Copmbine all role definitions form all supplied archetypes into a single set
	allRoleDefinitions := mapset.NewThreadUnsafeSet[string]()
	for _, archetype := range req.archetypes {
		allRoleDefinitions = allRoleDefinitions.Union(archetype.RoleDefinitions)
	}
	for name := range allRoleDefinitions.Iter() {
		newroledef, err := h.alzlib.RoleDefinition(name)
		if err != nil {
			return nil, fmt.Errorf("Hierarchy.AddManagementGroup(): role definition `%s` in management group `%s` does not exist in the library", name, req.id)
		}
		mg.roleDefinitions[name] = newroledef
	}

	// set the hierarchy on the management group.
	mg.hierarchy = h

	// add the management group to the deployment.
	h.mgs[req.id] = mg

	// run Update to change all refs, etc.
	if err := h.mgs[req.id].update(nil); err != nil {
		return nil, fmt.Errorf("Hierarchy.AddManagementGroup: adding `%s` error updating assets at scope %w", req.id, err)
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
