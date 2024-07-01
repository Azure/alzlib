// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"fmt"
	"strings"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/brunoga/deep"
	mapset "github.com/deckarep/golang-set/v2"
)

// HierarchyManagementGroup represents an Azure Management Group within a hierarchy, with links to parent and children.
// Note: this is not thread safe, and should not be used concurrently without an external mutex.
type HierarchyManagementGroup struct {
	children              mapset.Set[*HierarchyManagementGroup]  // The children of the management group.
	displayName           string                                 // The display name of the management group.
	exists                bool                                   // Whether the management group already exists in the hierarchy.
	hierarchy             *Hierarchy                             // The hierarchy that the management group belongs to.
	id                    string                                 // The name of the management group, forming the last part of the resource id.
	level                 int                                    // The level of the management group in the hierarchy.
	location              string                                 // The default location to use for artifacts in the management group.
	parent                *HierarchyManagementGroup              // The internal parent management group - will be nil if parent is external.
	parentExternal        *string                                // The external parent management group - will be nil if parent is internal.
	policyAssignments     map[string]*assets.PolicyAssignment    // The policy assignments in the management group.
	policyDefinitions     map[string]*assets.PolicyDefinition    // The policy definitions in the management group.
	policyRoleAssignments mapset.Set[PolicyRoleAssignment]       // The additional role assignments needed for the policy assignments.
	policySetDefinitions  map[string]*assets.PolicySetDefinition // The policy set definitions in the management group.
	roleDefinitions       map[string]*assets.RoleDefinition      // The role definitions in the management group.
}

// managementGroupAddRequest represents the request to add a management group to the hierarchy.
type managementGroupAddRequest struct {
	id               string              // The name of the management group, forming the last part of the resource id.
	displayName      string              // The display name of the management group.
	exists           bool                // Whether the management group already exists in the hierarchy.
	parentId         string              // The name of the parent management group.
	parentIsExternal bool                // If true, the parent management group is external to the hierarchy.
	archetypes       []*alzlib.Archetype // The archetypes to use for the management group.
	level            int                 // The level of the management group in the hierarchy.
	location         string              // The default location to use for artifacts in the management group.
}

// PolicyRoleAssignment represents the role assignments that need to be created for a management group.
// Since we could be using system assigned identities, we don't know the principal ID until after the deployment.
// Therefore this data can be used to create the role assignments after the deployment.
type PolicyRoleAssignment struct {
	RoleDefinitionId  string
	Scope             string
	AssignmentName    string
	ManagementGroupId string
}

// Children returns the children of the management group.
func (alzmg *HierarchyManagementGroup) Children() []*HierarchyManagementGroup {
	return alzmg.children.ToSlice()
}

// DisplayName returns the display name of the management group.
func (mg *HierarchyManagementGroup) DisplayName() string {
	return mg.displayName
}

// Name returns the name/id of the management group.
func (mg *HierarchyManagementGroup) Name() string {
	return mg.id
}

// HasParent returns a bool value depending on whether the management group has a given parent.
// Only works for internal parents.
func (mg *HierarchyManagementGroup) HasParent(id string) bool {
	if mg.parentExternal != nil || mg.parent == nil {
		return false
	}
	if mg.parent.id == id {
		return true
	}
	return mg.parent.HasParent(id)
}

// ParentId returns the ID of the parent management group.
// If the parent is external, this will be preferred.
// If neither are set an empty string is returned (though this should never happen).
func (mg *HierarchyManagementGroup) ParentId() string {
	if mg.parentExternal != nil {
		return *mg.parentExternal
	}
	if mg.parent != nil {
		return mg.parent.id
	}
	return ""
}

// Parent returns parent *AlzManagementGroup.
// If the parent is external, the result will be nil.
func (mg *HierarchyManagementGroup) Parent() *HierarchyManagementGroup {
	if mg.parentExternal != nil {
		return nil
	}
	return mg.parent
}

// ParentIsExternal returns a bool value depending on whether the parent MG is external or not.
func (mg *HierarchyManagementGroup) ParentIsExternal() bool {
	if mg.parentExternal != nil && *mg.parentExternal != "" {
		return true
	}
	return false
}

// Exists returns a bool value depending on whether the management group exists.
func (mg *HierarchyManagementGroup) Exists() bool {
	return mg.exists
}

// Level returns the level of the management group in the hierarchy.
func (mg *HierarchyManagementGroup) Level() int {
	return mg.level
}

// Location returns the default location to use for artifacts in the management group.
func (mg *HierarchyManagementGroup) Location() string {
	return mg.location
}

// ResourceId returns the resource ID of the management group.
func (mg *HierarchyManagementGroup) ResourceId() string {
	return fmt.Sprintf(ManagementGroupIdFmt, mg.id)
}

// PolicyAssignmentMap returns a copy of the policy assignments map.
func (mg *HierarchyManagementGroup) PolicyAssignmentMap() map[string]*assets.PolicyAssignment {
	return copyMap[string, *assets.PolicyAssignment](mg.policyAssignments)
}

// PolicyDefinitionsMap returns a copy of the policy definitions map.
func (mg *HierarchyManagementGroup) PolicyDefinitionsMap() map[string]*assets.PolicyDefinition {
	return copyMap[string, *assets.PolicyDefinition](mg.policyDefinitions)
}

// PolicySetDefinitionsMap returns a copy of the policy definitions map.
func (mg *HierarchyManagementGroup) PolicySetDefinitionsMap() map[string]*assets.PolicySetDefinition {
	return copyMap[string, *assets.PolicySetDefinition](mg.policySetDefinitions)
}

// RoleDefinitionsMap returns a copy of the role definitions map.
func (alzmg *HierarchyManagementGroup) RoleDefinitionsMap() map[string]*assets.RoleDefinition {
	return copyMap[string, *assets.RoleDefinition](alzmg.roleDefinitions)
}

// generatePolicyAssignmentAdditionalRoleAssignments generates the additional role assignment data needed for the policy assignments
// It should be run once the policy assignments map has been fully populated for a given HierarchyManagementGroup.
// It will iterate through all policy assignments and generate the additional role assignments for each one,
// storing them in the AdditionalRoleAssignmentsByPolicyAssignment map.
func (mg *HierarchyManagementGroup) generatePolicyAssignmentAdditionalRoleAssignments() error {
	for paName, pa := range mg.policyAssignments {
		// we only care about policy assignments that use an identity
		if pa.IdentityType() == armpolicy.ResourceIdentityTypeNone {
			continue
		}

		// get the policy definition name using the resource id
		policyDefinitionRef, err := pa.ReferencedPolicyDefinitionResourceId()
		if err != nil {
			return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: error getting referenced policy definition type for policy assignment `%s`: %w", paName, err)
		}

		switch policyDefinitionRef.ResourceType.Type {
		case "policyDefinitions":
			// check the definition exists in the AlzLib
			pd, err := mg.hierarchy.alzlib.PolicyDefinition(policyDefinitionRef.Name)
			if err != nil {
				return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: policy definition `%s`, referenced by `%s` not found in AlzLib", policyDefinitionRef.Name, paName)
			}
			// get the role definition ids from the policy definition and add to the additional role assignment data
			rdids, err := pd.NormalizedRoleDefinitionResourceIds()
			if err != nil {
				return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: error getting role definition ids for policy definition `%s`: %w", *pd.Name, err)
			}
			if len(rdids) == 0 {
				return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: policy definition `%s` has no role definition ids", *pd.Name)
			}
			for _, rdid := range rdids {
				mg.policyRoleAssignments.Add(PolicyRoleAssignment{
					Scope:             mg.ResourceId(),
					RoleDefinitionId:  rdid,
					AssignmentName:    paName,
					ManagementGroupId: mg.id,
				})
			}

			// for each parameter with assignPermissions = true
			// add the additional role assignment data unless the parameter value is empty
			assignPermissionParams, err := pd.AssignPermissionsParameterNames()
			if err != nil {
				return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: error getting assign permissions parameter names for policy definition `%s`: %w", *pd.Name, err)
			}
			for _, paramName := range assignPermissionParams {

				paParamVal, err := pa.ParameterValueAsString(paramName)
				if err != nil {
					return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: error getting parameter value for parameter `%s` in policy assignment `%s`: %w", paramName, paName, err)
				}
				if paParamVal == "" {
					continue
				}
				resId, err := arm.ParseResourceID(paParamVal)
				if err != nil {
					continue
				}
				for _, rdid := range rdids {
					mg.policyRoleAssignments.Add(PolicyRoleAssignment{
						Scope:             resId.String(),
						RoleDefinitionId:  rdid,
						AssignmentName:    paName,
						ManagementGroupId: mg.id,
					})
				}
			}

		case "policySetDefinitions":
			psd, err := mg.hierarchy.alzlib.PolicySetDefinition(policyDefinitionRef.Name)
			if err != nil {
				return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: policy set definition `%s`, referenced by `%s` not found in AlzLib", policyDefinitionRef.Name, paName)
			}
			pdRefs, err := psd.PolicyDefinitionReferences()
			if err != nil {
				return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: error getting referenced policy definition names for policy set definition %s: %w", *psd.Name, err)
			}
			// for each policy definition in the policy set definition
			for _, pdRef := range pdRefs {
				pdName, err := assets.NameFromResourceId(*pdRef.PolicyDefinitionID)
				if err != nil {
					return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: error getting policy definition name from id `%s`: %w", *pdRef.PolicyDefinitionID, err)
				}
				pd, err := mg.hierarchy.alzlib.PolicyDefinition(pdName)
				if err != nil {
					return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: policy definition `%s`, referenced by `%s` not found in AlzLib", pdName, *psd.Name)
				}

				// get the role definition ids from the policy definition and add to the additional role assignment data
				rdids, err := pd.NormalizedRoleDefinitionResourceIds()
				if err != nil {
					return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: error getting role definition ids for policy definition %s: %w", pdName, err)
				}
				for _, rdid := range rdids {
					mg.policyRoleAssignments.Add(PolicyRoleAssignment{
						Scope:             mg.ResourceId(),
						RoleDefinitionId:  rdid,
						AssignmentName:    paName,
						ManagementGroupId: mg.id,
					})
				}

				// for each parameter with assignPermissions = true
				// add the additional scopes to the additional role assignment data
				// to do this we have to map the assignment parameter value to the policy definition parameter value
				for paramName, paramVal := range pd.Properties.Parameters {
					if paramVal.Metadata == nil || paramVal.Metadata.AssignPermissions == nil || !*paramVal.Metadata.AssignPermissions {
						continue
					}
					// get the parameter value from the policy reference within the set definition
					if _, ok := pd.Properties.Parameters[paramName]; !ok {
						return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: parameter `%s` not found in policy definition `%s`", paramName, *pd.Name)
					}
					pdrefParamVal := pdRef.Parameters[paramName].Value
					pdrefParamValStr, ok := pdrefParamVal.(string)
					if !ok {
						return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: parameter `%s` value in policy definition `%s` is not a string", paramName, *pd.Name)
					}
					// extract the assignment exposed policy set parameter name from the ARM function used in the policy definition reference
					paParamName, err := extractParameterNameFromArmFunction(pdrefParamValStr)
					if err != nil {
						return fmt.Errorf("ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: error extracting parameter name from ARM function `%s`: %w", pdrefParamValStr, err)
					}

					// if the parameter in the assignment doesn't exist, skip it
					paParamVal, err := pa.ParameterValueAsString(paParamName)
					if err != nil {
						continue
					}
					resid, err := arm.ParseResourceID(paParamVal)
					if err != nil {
						continue
					}
					for _, rdid := range rdids {
						mg.policyRoleAssignments.Add(PolicyRoleAssignment{
							Scope:             resid.String(),
							RoleDefinitionId:  rdid,
							AssignmentName:    paName,
							ManagementGroupId: mg.id,
						})
					}
				}
			}
		}
	}
	return nil
}

// update will update the AlzManagementGroup resources with the correct resource ids, references, etc.
// Make sure to pass in any updates to the policy assignment parameter values.
func (mg *HierarchyManagementGroup) update(papv PolicyAssignmentsParameterValues) error {
	pd2mg := mg.hierarchy.policyDefinitionToMg()
	psd2mg := mg.hierarchy.policySetDefinitionToMg()

	// re-write the policy definition ID property to be the current MG name.
	updatePolicyDefinitions(mg)

	// re-write the policy set definition ID property and go through the referenced definitions
	// and write the definition id if it's custom.
	if err := updatePolicySetDefinitions(mg, pd2mg); err != nil {
		return fmt.Errorf("HierarchyManagementGroup.update: error updating policy set definitions for mg `%s`: %w", mg.id, err)
	}

	// re-write the assignableScopes for the role definitions.
	updateRoleDefinitions(mg)

	if err := updatePolicyAsignments(mg, pd2mg, psd2mg, papv); err != nil {
		return fmt.Errorf("HierarchyManagementGroup.update: error updating policy assignments: %w", err)
	}
	return nil
}

// ModifyPolicyAssignment modifies an existing policy assignment in the management group.
// It will deep merge the supplied assignments with the existing assignments.
func (alzmg *HierarchyManagementGroup) ModifyPolicyAssignment(
	name string,
	parameters map[string]*armpolicy.ParameterValuesValue,
	enforcementMode *armpolicy.EnforcementMode,
	nonComplianceMessages []*armpolicy.NonComplianceMessage,
	identity *armpolicy.Identity,
	resourceSelectors []*armpolicy.ResourceSelector,
	overrides []*armpolicy.Override,
) error {
	if _, ok := alzmg.policyAssignments[name]; !ok {
		return fmt.Errorf("HierarchyManagementGroup.ModifyPolicyAssignment: policy assignment %s not found in management group %s", name, alzmg.id)
	}

	if alzmg.policyAssignments[name].Properties == nil {
		return fmt.Errorf("HierarchyManagementGroup.ModifyPolicyAssignment: properties for policy assignment %s in management group %s is nil", name, alzmg.id)
	}

	if alzmg.policyAssignments[name].Properties.Parameters == nil && len(parameters) > 0 {
		alzmg.policyAssignments[name].Properties.Parameters = make(map[string]*armpolicy.ParameterValuesValue, len(parameters))
	}

	for k, v := range parameters {
		alzmg.policyAssignments[name].Properties.Parameters[k] = v
	}

	if enforcementMode != nil {
		alzmg.policyAssignments[name].Properties.EnforcementMode = enforcementMode
	}

	if nonComplianceMessages != nil {
		alzmg.policyAssignments[name].Properties.NonComplianceMessages = nonComplianceMessages
	}

	if resourceSelectors != nil {
		alzmg.policyAssignments[name].Properties.ResourceSelectors = resourceSelectors
	}

	if overrides != nil {
		alzmg.policyAssignments[name].Properties.Overrides = overrides
	}

	if identity != nil {
		alzmg.policyAssignments[name].Identity = identity
	}
	return nil
}

// extractParameterNameFromArmFunction extracts the parameter name from an ARM function.
func extractParameterNameFromArmFunction(value string) (string, error) {
	// value is of the form "[parameters('parameterName')]".
	if !strings.HasPrefix(value, "[parameters('") || !strings.HasSuffix(value, "')]") {
		return "", fmt.Errorf("value is not a parameter reference")
	}
	return value[13 : len(value)-3], nil
}

// updatePolicyDefinitions re-writes the policy definition resource IDs for the correct management group.
func updatePolicyDefinitions(mg *HierarchyManagementGroup) {
	for k, v := range mg.policyDefinitions {
		v.ID = to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, mg.id, k))
	}
}

// These for loops re-write the referenced policy definition resource IDs
// for all policy sets.
// It looks up the policy definition names that are in all archetypes in the Deployment.
// If it is found, the definition reference id is re-written with the correct management group name.
// If it is not found, we assume that it's built-in.
func updatePolicySetDefinitions(mg *HierarchyManagementGroup, pd2mg map[string]string) error {
	for k, psd := range mg.policySetDefinitions {
		psd.ID = to.Ptr(fmt.Sprintf(PolicySetDefinitionIdFmt, mg.id, k))
		refs, err := psd.PolicyDefinitionReferences()
		if err != nil {
			return fmt.Errorf("updatePolicySetDefinitions: error getting policy definition references for policy set definition %s: %w", k, err)
		}
		for _, pd := range refs {
			pdname, err := assets.NameFromResourceId(*pd.PolicyDefinitionID)
			if err != nil {
				return fmt.Errorf("updatePolicySetDefinitions: error getting policy definition name from resource id %s: %w", *pd.PolicyDefinitionID, err)
			}
			if mgname, ok := pd2mg[pdname]; ok {
				pd.PolicyDefinitionID = to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, mgname, pdname))
			}
		}
	}
	return nil
}

func updatePolicyAsignments(mg *HierarchyManagementGroup, pd2mg, psd2mg map[string]string, papv PolicyAssignmentsParameterValues) error {
	for assignmentName, params := range papv {
		pa, ok := mg.policyAssignments[assignmentName]
		if !ok {
			continue
		}
		if pa.Properties.Parameters == nil {
			pa.Properties.Parameters = make(map[string]*armpolicy.ParameterValuesValue, 1)
		}
		for param, value := range params {
			pa.Properties.Parameters[param] = value
		}
	}

	// Update resource ids and refs.
	for assignmentName, assignment := range mg.policyAssignments {
		assignment.ID = to.Ptr(fmt.Sprintf(PolicyAssignmentIdFmt, mg.id, assignmentName))
		assignment.Properties.Scope = to.Ptr(fmt.Sprintf(ManagementGroupIdFmt, mg.id))
		if assignment.Location != nil {
			assignment.Location = &mg.location
		}

		// rewrite the referenced policy definition id
		// if the policy definition is in the list.
		pdRes, err := assignment.ReferencedPolicyDefinitionResourceId()
		if err != nil {
			return fmt.Errorf("updatePolicyAssignments: error parsing policy definition id for policy assignment %s: %w", assignmentName, err)
		}

		switch strings.ToLower(pdRes.ResourceType.Type) {
		case "policydefinitions":
			if mgname, ok := pd2mg[pdRes.Name]; ok {
				if mgname != mg.id && !mg.HasParent(mgname) {
					return fmt.Errorf("updatePolicyAssignments: policy assignment %s has a policy definition %s that is not in the same hierarchy", assignmentName, pdRes.Name)
				}
				assignment.Properties.PolicyDefinitionID = to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, mgname, pdRes.Name))
			}
		case "policysetdefinitions":
			if mgname, ok := psd2mg[pdRes.Name]; ok {
				if mgname != mg.id && !mg.HasParent(mgname) {
					return fmt.Errorf("updatePolicyAssignments: policy assignment %s has a policy set definition %s that is not in the same hierarchy", assignmentName, pdRes.Name)
				}
				assignment.Properties.PolicyDefinitionID = to.Ptr(fmt.Sprintf(PolicySetDefinitionIdFmt, mgname, pdRes.Name))
			}
		default:
			return fmt.Errorf("updatePolicyAssignments: policy assignment %s has invalid referenced definition/set resource type with id: %s", assignmentName, pdRes.Name)
		}
	}
	return nil
}

func updateRoleDefinitions(alzmg *HierarchyManagementGroup) {
	for _, roledef := range alzmg.roleDefinitions {
		u := uuidV5(alzmg.id, *roledef.Name)
		roledef.ID = to.Ptr(fmt.Sprintf(RoleDefinitionIdFmt, alzmg.id, u))
		if roledef.Properties.AssignableScopes == nil || len(roledef.Properties.AssignableScopes) == 0 {
			roledef.Properties.AssignableScopes = make([]*string, 1)
		}
		roledef.Properties.AssignableScopes[0] = to.Ptr(alzmg.ResourceId())
	}
}

func newManagementGroup() *HierarchyManagementGroup {
	return &HierarchyManagementGroup{
		policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
		policyDefinitions:     make(map[string]*assets.PolicyDefinition),
		policySetDefinitions:  make(map[string]*assets.PolicySetDefinition),
		policyAssignments:     make(map[string]*assets.PolicyAssignment),
		roleDefinitions:       make(map[string]*assets.RoleDefinition),
	}
}

// copyMap takes a map and returns a map with a deep copy of the values.
func copyMap[E comparable, T any](m map[E]T) map[E]T {
	m2 := make(map[E]T, len(m))
	for k, v := range m {
		m2[k] = deep.MustCopy(v)
	}
	return m2
}
