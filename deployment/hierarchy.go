// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
)

const (
	// ManagementGroupIDFmt is the format string for management group resource IDs in Azure.
	ManagementGroupIDFmt = "/providers/Microsoft.Management/managementGroups/%s"

	// PolicyAssignmentIDFmt is the format string for policy assignment resource IDs in Azure.
	PolicyAssignmentIDFmt = "/providers/Microsoft.Management/managementGroups/%s" +
		"/providers/Microsoft.Authorization/policyAssignments/%s"

	// PolicyDefinitionIDFmt is the format string for policy definition resource IDs in Azure.
	PolicyDefinitionIDFmt = "/providers/Microsoft.Management/managementGroups/%s" +
		"/providers/Microsoft.Authorization/policyDefinitions/%s"

	// PolicySetDefinitionIDFmt is the format string for policy set definition resource IDs in Azure.
	PolicySetDefinitionIDFmt = "/providers/Microsoft.Management/managementGroups/%s" +
		"/providers/Microsoft.Authorization/policySetDefinitions/%s"

	// RoleDefinitionIDFmt is the format string for role definition resource IDs in Azure.
	RoleDefinitionIDFmt = "/providers/Microsoft.Management/managementGroups/%s" +
		"/providers/Microsoft.Authorization/roleDefinitions/%s"
)

// Hierarchy represents a deployment of Azure management group hierarchy.
// Do not create this struct directly, use NewHierarchy instead.
type Hierarchy struct {
	mgs    map[string]*HierarchyManagementGroup
	alzlib *alzlib.AlzLib
	mu     *sync.RWMutex
}

// NewHierarchy creates a new Hierarchy with the given AlzLib.
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

// ManagementGroupNames returns the management group names as a slice of string.
func (h *Hierarchy) ManagementGroupNames() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	res := make([]string, len(h.mgs))
	i := 0

	for mgname := range h.mgs {
		res[i] = mgname
		i++
	}

	slices.Sort(res)

	return res
}

// ManagementGroupsAtLevel returns the management groups from the given level as a map of string to
// *HierarchyManagementGroup.
func (h *Hierarchy) ManagementGroupsAtLevel(level int) map[string]*HierarchyManagementGroup {
	h.mu.RLock()
	defer h.mu.RUnlock()

	res := make(map[string]*HierarchyManagementGroup)

	for mgname, mg := range h.mgs {
		if mg.level != level {
			continue
		}

		res[mgname] = mg
	}

	return h.mgs
}

// FromArchitecture creates a hierarchy from the given architecture.
func (h *Hierarchy) FromArchitecture(
	ctx context.Context,
	arch, externalParentID, location string,
) error {
	architecture := h.alzlib.Architecture(arch)
	if architecture == nil {
		return fmt.Errorf("Hierarchy.FromArchitecture: getting architecture `%s`", arch)
	}
	// Get the architecture root management groups.
	for _, a := range architecture.RootMgs() {
		if err := recurseAddManagementGroup(ctx, h, a, externalParentID, location, true, 0); err != nil {
			return fmt.Errorf(
				"Hierarchy.FromArchitecture: recursion error on architecture `%s` %w",
				arch,
				err,
			)
		}
	}

	return nil
}

// PolicyRoleAssignments returns the policy assignments required for the hierarchy.
// This error returned bay be a PolicyRoleAssignmentErrors, which contains a slice of errors.
// This is so that callers can choose to issue a warning here instead of halting the process.
func (h *Hierarchy) PolicyRoleAssignments(
	_ context.Context,
) (mapset.Set[PolicyRoleAssignment], error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var errs *PolicyRoleAssignmentErrors

	res := mapset.NewThreadUnsafeSet[PolicyRoleAssignment]()
	// Get the policy assignments for each management group.
	for _, mg := range h.mgs {
		if err := mg.generatePolicyAssignmentAdditionalRoleAssignments(); err != nil {
			var thisErrs *PolicyRoleAssignmentErrors
			if errors.As(err, &thisErrs) {
				if errs == nil {
					errs = NewPolicyRoleAssignmentErrors()
				}

				errs.Add(thisErrs.Errors()...)

				continue
			}

			return nil, fmt.Errorf(
				"Hierarchy.PolicyRoleAssignments: generating additional role assignments for management group `%s`: %w",
				mg.id,
				err,
			)
		}

		res = res.Union(mg.policyRoleAssignments)
	}

	if errs != nil {
		return res, errs
	}

	return res, nil
}

// AddDefaultPolicyAssignmentValue adds a default policy assignment value to the hierarchy.
func (h *Hierarchy) AddDefaultPolicyAssignmentValue(
	_ context.Context,
	defaultName string,
	defaultValue *armpolicy.ParameterValuesValue,
) error {
	defs := h.alzlib.PolicyDefaultValue(defaultName)
	if defs == nil {
		return fmt.Errorf(
			"Hierarchy.AddDefaultPolicyAssignmentValue: A default with name `%s` does not exist",
			defaultName,
		)
	}
	// Get the policy assignments for each management group.
	for _, mg := range h.mgs {
		for assignment, params := range defs.PolicyAssignment2ParameterMap() {
			if _, ok := mg.policyAssignments[assignment]; !ok {
				continue
			}

			newParams := make(map[string]*armpolicy.ParameterValuesValue)
			for param := range params.Iter() {
				newParams[param] = defaultValue
			}

			if err := mg.ModifyPolicyAssignment(assignment, newParams, nil, nil, nil, nil, nil); err != nil {
				return fmt.Errorf(
					"Hierarchy.AddDefaultPolicyAssignmentValue: adding default `%s` policy assignment value "+
						"to management group `%s` for policy assignment `%s`: %w",
					defaultName,
					mg.id,
					assignment,
					err,
				)
			}
		}
	}

	return nil
}

func recurseAddManagementGroup(
	ctx context.Context,
	h *Hierarchy,
	archMg *alzlib.ArchitectureManagementGroup,
	parent, location string,
	externalParent bool,
	level int,
) error {
	req := managementGroupAddRequest{
		archetypes:       archMg.Archetypes(),
		displayName:      archMg.DisplayName(),
		exists:           archMg.Exists(),
		id:               archMg.ID(),
		level:            level,
		location:         location,
		parentID:         parent,
		parentIsExternal: externalParent,
	}
	if _, err := h.addManagementGroup(ctx, req); err != nil {
		return fmt.Errorf(
			"Hierarchy.recurseAddManagementGroup: adding management group `%s`: %w",
			archMg.ID(),
			err,
		)
	}

	for _, child := range archMg.Children() {
		if err := recurseAddManagementGroup(ctx, h, child, archMg.ID(), location, false, level+1); err != nil {
			return err
		}
	}

	return nil
}

// addManagementGroup adds a management group to the hierarchy, with a parent if specified.
// If the parent is not specified, the management group is considered the root of the hierarchy.
// The archetype should have been obtained using the `AlzLib.CopyArchetype` method.
// This allows for customization and ensures the correct policy assignment values have been set.
func (h *Hierarchy) addManagementGroup(
	ctx context.Context,
	req managementGroupAddRequest,
) (*HierarchyManagementGroup, error) {
	if req.parentID == "" {
		return nil, fmt.Errorf(
			"Hierarchy.AddManagementGroup: parent management group not specified for `%s`",
			req.id,
		)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.mgs[req.id]; exists {
		return nil, fmt.Errorf(
			"Hierarchy.AddManagementGroup: management group %s already exists",
			req.id,
		)
	}

	mg := newManagementGroup()

	mg.id = req.id
	mg.displayName = req.displayName
	mg.exists = req.exists
	mg.level = req.level
	mg.children = mapset.NewSet[*HierarchyManagementGroup]()
	mg.location = req.location

	if req.parentIsExternal {
		if _, ok := h.mgs[req.parentID]; ok {
			return nil, fmt.Errorf(
				"Hierarchy.AddManagementGroup: external parent management group set, but already exists %s",
				req.parentID,
			)
		}

		mg.parentExternal = to.Ptr(req.parentID)
	}

	if !req.parentIsExternal {
		parentMg, ok := h.mgs[req.parentID]
		if !ok {
			return nil, fmt.Errorf(
				"Hierarchy.AddManagementGroup: parent management group not found %s",
				req.parentID,
			)
		}

		mg.parent = parentMg
		h.mgs[req.parentID].children.Add(mg)
	}

	// Get the policy definitions and policy set definitions referenced by the policy assignments.
	assignedPolicyDefinitions := make([]alzlib.BuiltInRequest, 0, 100)

	// Combine all assignments from all supplied archetypes into a single set
	allPolicyAssignments := mapset.NewThreadUnsafeSet[string]()
	for _, archetype := range req.archetypes {
		allPolicyAssignments = allPolicyAssignments.Union(archetype.PolicyAssignments)
	}

	for pa := range allPolicyAssignments.Iter() {
		polAssign := h.alzlib.PolicyAssignment(pa)
		if polAssign == nil {
			return nil, fmt.Errorf(
				"Hierarchy.AddManagementGroup: policy assignment `%s` referenced in management group `%s` "+
					"does not exist in the library",
				pa,
				req.id,
			)
		}

		referencedResourceID, definitionVersion, err := polAssign.ReferencedPolicyDefinitionResourceIDAndVersion()
		if err != nil {
			return nil, fmt.Errorf(
				"Hierarchy.AddManagementGroup: getting referenced policy definition resource ID "+
					"for policy assignment `%s` in management group `%s`: %w",
				pa,
				req.id,
				err,
			)
		}

		assignedPolicyDefinitions = append(assignedPolicyDefinitions, alzlib.BuiltInRequest{
			ResourceID: referencedResourceID,
			Version:    definitionVersion,
		})
	}

	// Definitions are retrieved only at the time of adding the management group to the hierarchy.
	if err := h.alzlib.GetDefinitionsFromAzure(ctx, assignedPolicyDefinitions); err != nil {
		return nil, fmt.Errorf(
			"Hierarchy.AddManagementGroup: adding mg `%s` error getting policy definitions from Azure: %w",
			req.id,
			err,
		)
	}

	// Now that we are sure that we have all the definitions in the library,
	// make copies of the archetype resources for modification in the Deployment management group.

	// Combine all policy definitions from all supplied archetypes into a single set
	allPolicyDefinitions := mapset.NewThreadUnsafeSet[string]()
	for _, archetype := range req.archetypes {
		allPolicyDefinitions = allPolicyDefinitions.Union(archetype.PolicyDefinitions)
	}

	for name := range allPolicyDefinitions.Iter() {
		defName, defVersion := alzlib.SplitNameAndVersion(name)

		newDef := h.alzlib.PolicyDefinition(defName, defVersion)
		if newDef == nil {
			return nil, fmt.Errorf(
				"Hierarchy.AddManagementGroup: policy definition `%s` in management group `%s` does not exist in the library",
				name,
				req.id,
			)
		}

		mg.policyDefinitions[name] = newDef
	}
	// Combine all policy set definitions form all supplied archetypes into a single set
	allPolicySetDefinitions := mapset.NewThreadUnsafeSet[string]()
	for _, archetype := range req.archetypes {
		allPolicySetDefinitions = allPolicySetDefinitions.Union(archetype.PolicySetDefinitions)
	}

	for name := range allPolicySetDefinitions.Iter() {
		defName, defVersion := alzlib.SplitNameAndVersion(name)

		newSetDef := h.alzlib.PolicySetDefinition(defName, defVersion)
		if newSetDef == nil {
			return nil, fmt.Errorf(
				"Hierarchy.AddManagementGroup(): policy set definition `%s` in management group `%s` does not exist in the library",
				alzlib.JoinNameAndVersion(name, defVersion),
				req.id,
			)
		}

		mg.policySetDefinitions[name] = newSetDef
	}
	// Now that the policy definitions and policy set definitions have been copied, we can add the
	// policy assignments
	for name := range allPolicyAssignments.Iter() {
		newpolassign := h.alzlib.PolicyAssignment(name)
		if newpolassign == nil {
			return nil, fmt.Errorf(
				"Hierarchy.AddManagementGroup(): policy assignment `%s` in management group `%s` does not exist in the library",
				name,
				req.id,
			)
		}
		// Check if the referenced policy is a set and if its parameters match the parameters in the
		// policy definitions
		refPdID, refVer, _ := newpolassign.ReferencedPolicyDefinitionResourceIDAndVersion()
		if strings.ToLower(refPdID.ResourceType.Type) == "policysetdefinitions" {
			psd := h.alzlib.PolicySetDefinition(refPdID.Name, refVer)

			rfs := psd.PolicyDefinitionReferences()
			for _, rf := range rfs {
				resID, _ := arm.ParseResourceID(*rf.PolicyDefinitionID)
				pd := h.alzlib.PolicyDefinition(resID.Name, rf.DefinitionVersion)

				if pd == nil {
					return nil, fmt.Errorf(
						"Hierarchy.AddManagementGroup(): policy definition `%s` in policy set definition `%s` "+
							"in management group `%s` does not exist in the library",
						alzlib.JoinNameAndVersion(resID.Name, rf.DefinitionVersion),
						refPdID.Name,
						req.id,
					)
				}

				for param := range rf.Parameters {
					if pd.Parameter(param) == nil {
						return nil, fmt.Errorf(
							"Hierarchy.AddManagementGroup(): parameter `%s` in policy set definition `%s` "+
								"does not match a parameter in referenced definition `%s` in management group `%s`",
							param,
							*psd.Name,
							alzlib.JoinNameAndVersion(*pd.Name, rf.DefinitionVersion),
							req.id,
						)
					}
				}
			}
		}

		mg.policyAssignments[name] = newpolassign
	}

	// Combine all role definitions form all supplied archetypes into a single set
	allRoleDefinitions := mapset.NewThreadUnsafeSet[string]()
	for _, archetype := range req.archetypes {
		allRoleDefinitions = allRoleDefinitions.Union(archetype.RoleDefinitions)
	}

	for name := range allRoleDefinitions.Iter() {
		newroledef := h.alzlib.RoleDefinition(name)
		if newroledef == nil {
			return nil, fmt.Errorf(
				"Hierarchy.AddManagementGroup(): role definition `%s` in management group `%s` does not exist in the library",
				name,
				req.id,
			)
		}

		mg.roleDefinitions[name] = newroledef
	}

	// set the hierarchy on the management group.
	mg.hierarchy = h

	// add the management group to the deployment.
	h.mgs[req.id] = mg

	// run Update to change all refs, etc.
	if err := h.mgs[req.id].update(h.alzlib.Options.UniqueRoleDefinitions); err != nil {
		return nil, fmt.Errorf(
			"Hierarchy.AddManagementGroup: adding `%s` error updating assets at scope %w",
			req.id,
			err,
		)
	}

	return mg, nil
}

// policyDefinitionToMg returns a map of policy definition names to the deployed management group
// name.
func (h *Hierarchy) policyDefinitionToMg() map[string]mapset.Set[string] {
	res := make(map[string]mapset.Set[string], 0)

	for mgname, mg := range h.mgs {
		for pdname := range mg.policyDefinitions {
			if _, ok := res[pdname]; !ok {
				res[pdname] = mapset.NewThreadUnsafeSet[string]()
			}

			res[pdname].Add(mgname)
		}
	}

	return res
}

// policyDefinitionToMg returns a map of policy set definition names to the deployed management
// group name.
func (h *Hierarchy) policySetDefinitionToMg() map[string]mapset.Set[string] {
	res := make(map[string]mapset.Set[string], 0)

	for mgname, mg := range h.mgs {
		for psdname := range mg.policySetDefinitions {
			if _, ok := res[psdname]; !ok {
				res[psdname] = mapset.NewThreadUnsafeSet[string]()
			}

			res[psdname].Add(mgname)
		}
	}

	return res
}

func uuidV5(s ...string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(strings.Join(s, "")))
}
