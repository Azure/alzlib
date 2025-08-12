// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/brunoga/deep"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/matt-FFFFFF/goarmfunctions"
)

// HierarchyManagementGroup represents an Azure Management Group within a hierarchy, with links to
// parent and children.
type HierarchyManagementGroup struct {
	children    mapset.Set[*HierarchyManagementGroup] // The children of the management group.
	displayName string                                // The display name of the management group.
	// Whether the management group already exists in the hierarchy.
	exists    bool
	hierarchy *Hierarchy // The hierarchy that the management group belongs to.
	// The name of the management group, forming the last part of the resource id.
	id    string
	level int // The level of the management group in the hierarchy.
	// The default location to use for artifacts in the management group.
	location string
	// The internal parent management group - will be nil if parent is external.
	parent *HierarchyManagementGroup
	// The external parent management group - will be nil if parent is internal.
	parentExternal    *string
	policyAssignments map[string]*assets.PolicyAssignment // The policy assignments in the management group.
	policyDefinitions map[string]*assets.PolicyDefinition // The policy definitions in the management group.
	// The additional role assignments needed for the policy assignments.
	policyRoleAssignments mapset.Set[PolicyRoleAssignment]
	policySetDefinitions  map[string]*assets.PolicySetDefinition // The policy set definitions in the management group.
	roleDefinitions       map[string]*assets.RoleDefinition      // The role definitions in the management group.
}

// managementGroupAddRequest represents the request to add a management group to the hierarchy.
type managementGroupAddRequest struct {
	id               string              // The name of the management group, forming the last part of the resource id.
	displayName      string              // The display name of the management group.
	exists           bool                // Whether the management group already exists in the hierarchy.
	parentID         string              // The name of the parent management group.
	parentIsExternal bool                // If true, the parent management group is external to the hierarchy.
	archetypes       []*alzlib.Archetype // The archetypes to use for the management group.
	level            int                 // The level of the management group in the hierarchy.
	location         string              // The default location to use for artifacts in the management group.
}

// PolicyRoleAssignment represents the role assignments that need to be created for a management
// group. Since we could be using system assigned identities, we don't know the principal ID until
// after the deployment.
// Therefore this data can be used to create the role assignments after the deployment.
type PolicyRoleAssignment struct {
	RoleDefinitionID  string `json:"role_definition_id,omitempty"`
	Scope             string `json:"scope,omitempty"`
	AssignmentName    string `json:"assignment_name,omitempty"`
	ManagementGroupID string `json:"management_group_id,omitempty"`
}

// Children returns the children of the management group.
func (mg *HierarchyManagementGroup) Children() []*HierarchyManagementGroup {
	return mg.children.ToSlice()
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

// ParentID returns the ID of the parent management group.
// If the parent is external, this will be preferred.
// If neither are set an empty string is returned (though this should never happen).
func (mg *HierarchyManagementGroup) ParentID() string {
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

// ResourceID returns the resource ID of the management group.
func (mg *HierarchyManagementGroup) ResourceID() string {
	return fmt.Sprintf(ManagementGroupIDFmt, mg.id)
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
func (mg *HierarchyManagementGroup) RoleDefinitionsMap() map[string]*assets.RoleDefinition {
	return copyMap[string, *assets.RoleDefinition](mg.roleDefinitions)
}

// generatePolicyAssignmentAdditionalRoleAssignments generates the additional role assignment data
// needed for the policy
// assignments
// It should be run once the policy assignments map has been fully populated for a given
// HierarchyManagementGroup. It will iterate through all policy assignments and generate the
// additional role assignments for each one,
// storing them in the AdditionalRoleAssignmentsByPolicyAssignment map.
func (mg *HierarchyManagementGroup) generatePolicyAssignmentAdditionalRoleAssignments() error {
	// Make a error collection type so we can return them in the error message without stopping the
	// process.
	// Upstream code can then decide what to do with them, issue warnings in stead of hard fail, etc.
	var errs *PolicyRoleAssignmentErrors

	for paName, pa := range mg.policyAssignments {
		// we only care about policy assignments that use an identity
		if pa.IdentityType() == armpolicy.ResourceIdentityTypeNone {
			continue
		}

		// get the policy definition name using the resource id
		policyDefinitionRef, err := pa.ReferencedPolicyDefinitionResourceID()
		if err != nil {
			return fmt.Errorf(
				"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
					"error getting referenced policy definition type for policy assignment `%s`: %w",
				paName,
				err,
			)
		}

		switch policyDefinitionRef.ResourceType.Type {
		case "policyDefinitions":
			// check the definition exists in the AlzLib
			pd := mg.hierarchy.alzlib.PolicyDefinition(policyDefinitionRef.Name)
			if pd == nil {
				return fmt.Errorf(
					"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
						"policy definition `%s`, referenced by `%s` not found in AlzLib",
					policyDefinitionRef.Name,
					paName,
				)
			}

			// get the role definition ids from the policy definition and add to the additional role
			// assignment data
			rdids, err := pd.NormalizedRoleDefinitionResourceIDs()
			if err != nil {
				return fmt.Errorf(
					"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
						"assignment `%s`, error getting role definition ids for policy definition `%s`: %w",
					paName,
					*pd.Name,
					err,
				)
			}

			if len(rdids) == 0 {
				return fmt.Errorf(
					"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
						"assignment `%s`, policy definition `%s` has no role definition ids",
					paName,
					*pd.Name,
				)
			}

			for _, rdid := range rdids {
				mg.policyRoleAssignments.Add(PolicyRoleAssignment{
					Scope:             mg.ResourceID(),
					RoleDefinitionID:  rdid,
					AssignmentName:    paName,
					ManagementGroupID: mg.id,
				})
			}

			// for each parameter with assignPermissions = true
			// add the additional role assignment data unless the parameter value is empty
			assignPermissionParams, err := pd.AssignPermissionsParameterNames()
			if err != nil {
				return fmt.Errorf(
					"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
						"error getting assign permissions parameter names for policy definition `%s`: %w",
					*pd.Name,
					err,
				)
			}

			for _, paramName := range assignPermissionParams {
				paramIsOptional, err := pd.ParameterIsOptional(paramName)
				if err != nil {
					return fmt.Errorf(
						"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
							"error getting parameter %s optional status for policy definition `%s`: %w",
						paramName,
						*pd.Name,
						err,
					)
				}

				paParamVal, err := pa.ParameterValueAsString(paramName)
				if err != nil && !paramIsOptional {
					return fmt.Errorf(
						"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
							"error getting parameter value for parameter `%s` in policy assignment `%s`: %w",
						paramName,
						paName,
						err,
					)
				}
				// We should assign permissions but the parameter os optional and doesn't have a value in
				// the assignment, so
				// skip.
				if err != nil && paramIsOptional {
					continue
				}

				if paParamVal == "" {
					continue
				}

				resID, err := arm.ParseResourceID(paParamVal)
				if err != nil {
					continue
				}

				for _, rdid := range rdids {
					mg.policyRoleAssignments.Add(PolicyRoleAssignment{
						Scope:             resID.String(),
						RoleDefinitionID:  rdid,
						AssignmentName:    paName,
						ManagementGroupID: mg.id,
					})
				}
			}

		case "policySetDefinitions":
			psd := mg.hierarchy.alzlib.PolicySetDefinition(policyDefinitionRef.Name)
			if psd == nil {
				return fmt.Errorf(
					"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
						"assignment `%s`, policy set `%s` not found in AlzLib",
					paName,
					policyDefinitionRef.Name,
				)
			}

			pdRefs := psd.PolicyDefinitionReferences()
			if pdRefs == nil {
				return fmt.Errorf(
					"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
						"assignment `%s`, error getting referenced policy definition names for policy set definition %s",
					paName,
					*psd.Name,
				)
			}
			// for each policy definition in the policy set definition
			for _, pdRef := range pdRefs {
				pdName, err := assets.NameFromResourceID(*pdRef.PolicyDefinitionID)
				if err != nil {
					return fmt.Errorf(
						"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
							"assignment `%s`, error getting policy definition name from policy set definition `%s`, with id `%s`: %w",
						paName,
						*psd.Name,
						*pdRef.PolicyDefinitionID,
						err,
					)
				}

				pd := mg.hierarchy.alzlib.PolicyDefinition(pdName)
				if pd == nil {
					return fmt.Errorf(
						"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
							"assignment `%s`, policy definition `%s`, referenced by `%s` not found in AlzLib",
						paName,
						pdName,
						*psd.Name,
					)
				}

				// get the role definition ids from the policy definition and add to the additional role
				// assignment data
				rdids, err := pd.NormalizedRoleDefinitionResourceIDs()
				if err != nil {
					return fmt.Errorf(
						"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
							"assignment `%s`, error getting role definition ids referenced in policy set `%s` for policy definition %s: %w",
						paName,
						*psd.Name,
						pdName,
						err,
					)
				}

				for _, rdid := range rdids {
					mg.policyRoleAssignments.Add(PolicyRoleAssignment{
						Scope:             mg.ResourceID(),
						RoleDefinitionID:  rdid,
						AssignmentName:    paName,
						ManagementGroupID: mg.id,
					})
				}

				// for each parameter with assignPermissions = true
				// add the additional scopes to the additional role assignment data
				// to do this we have to map the assignment parameter value to the policy definition
				// parameter value.
				for paramName, paramVal := range pd.Properties.Parameters {
					// If assignPermissions is not set then skip.
					if paramVal.Metadata == nil || paramVal.Metadata.AssignPermissions == nil ||
						!*paramVal.Metadata.AssignPermissions {
						continue
					}
					// get the parameter value from the policy reference within the set definition.
					if _, ok := pd.Properties.Parameters[paramName]; !ok {
						return fmt.Errorf(
							"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
								"assignment `%s` for policy set `%s`, parameter `%s` not found in refernced policy definition `%s`",
							paName,
							*psd.Name,
							paramName,
							*pd.Name,
						)
					}
					// use goarmfunctions to evaluate the ARM expression in the parameter value in the set
					// definition reference.
					scope, err := parseArmFunctionInPolicySetParameter(
						*pdRef.PolicyDefinitionReferenceID,
						paramName,
						&pa.Assignment,
						&psd.SetDefinition,
					)
					if err != nil {
						if errs == nil {
							errs = NewPolicyRoleAssignmentErrors()
						}

						errs.Add(
							NewPolicyRoleAssignmentError(
								paName,
								mg.id,
								paramName,
								*pdRef.PolicyDefinitionReferenceID,
								rdids,
								err,
							),
						)

						continue
					} // The value should be a string.

					scopeStr, ok := scope.(string)
					if !ok {
						if errs == nil {
							errs = NewPolicyRoleAssignmentErrors()
						}

						errs.Add(
							NewPolicyRoleAssignmentError(
								paName,
								mg.id,
								paramName,
								*pdRef.PolicyDefinitionReferenceID,
								rdids,
								fmt.Errorf(
									"ManagementGroup.GeneratePolicyAssignmentAdditionalRoleAssignments: "+
										"assignment `%s` for policy set `%s`, parameter `%s` value in policy definition `%s` is not a string",
									paName,
									*psd.Name,
									paramName,
									*pd.Name,
								),
							),
						)

						continue
					}
					// The value should be an ARM resource ID.
					resid, err := arm.ParseResourceID(scopeStr)
					if err != nil {
						if errs == nil {
							errs = NewPolicyRoleAssignmentErrors()
						}

						errs.Add(
							NewPolicyRoleAssignmentError(
								paName,
								mg.id,
								paramName,
								*pdRef.PolicyDefinitionReferenceID,
								rdids,
								err,
							),
						)

						continue
					}
					// if we got this far then we can add the role assignments.
					for _, rdid := range rdids {
						mg.policyRoleAssignments.Add(PolicyRoleAssignment{
							Scope:             resid.String(),
							RoleDefinitionID:  rdid,
							AssignmentName:    paName,
							ManagementGroupID: mg.id,
						})
					}
				}
			}
		}
	}

	if errs != nil {
		return errs
	}

	return nil
}

// update will update the AlzManagementGroup resources with the correct resource ids, references,
// etc.
// Make sure to pass in any updates to the policy assignment parameter values.
func (mg *HierarchyManagementGroup) update(uniqueRoleDefinitions bool) error {
	pd2mg := mg.hierarchy.policyDefinitionToMg()
	psd2mg := mg.hierarchy.policySetDefinitionToMg()

	// re-write the policy definition ID property to be the current MG name.
	updatePolicyDefinitions(mg)

	// re-write the policy set definition ID property and go through the referenced definitions
	// and write the definition id if it's custom.
	if err := updatePolicySetDefinitions(mg, pd2mg); err != nil {
		return fmt.Errorf(
			"HierarchyManagementGroup.update: error updating policy set definitions for mg `%s`: %w",
			mg.id,
			err,
		)
	}

	// re-write the assignableScopes for the role definitions.
	updateRoleDefinitions(mg, uniqueRoleDefinitions)

	if err := updatePolicyAsignments(mg, pd2mg, psd2mg); err != nil {
		return fmt.Errorf("HierarchyManagementGroup.update: error updating policy assignments: %w", err)
	}

	return nil
}

// ModifyPolicyAssignment modifies an existing policy assignment in the management group.
// It will deep merge the supplied assignments with the existing assignments.
func (mg *HierarchyManagementGroup) ModifyPolicyAssignment(
	name string,
	parameters map[string]*armpolicy.ParameterValuesValue,
	enforcementMode *armpolicy.EnforcementMode,
	nonComplianceMessages []*armpolicy.NonComplianceMessage,
	identity *armpolicy.Identity,
	resourceSelectors []*armpolicy.ResourceSelector,
	overrides []*armpolicy.Override,
) error {
	if _, ok := mg.policyAssignments[name]; !ok {
		return fmt.Errorf(
			"HierarchyManagementGroup.ModifyPolicyAssignment: policy assignment %s not found in management group %s",
			name,
			mg.id,
		)
	}

	if mg.policyAssignments[name].Properties == nil {
		return fmt.Errorf(
			"HierarchyManagementGroup.ModifyPolicyAssignment: properties for policy assignment %s in management group %s is nil",
			name,
			mg.id,
		)
	}

	if mg.policyAssignments[name].Properties.Parameters == nil && len(parameters) > 0 {
		mg.policyAssignments[name].Properties.Parameters = make(
			map[string]*armpolicy.ParameterValuesValue,
			len(parameters),
		)
	}

	for k, v := range parameters {
		// Only add parameter if it exists in the referenced policy definition.
		ref, err := mg.policyAssignments[name].ReferencedPolicyDefinitionResourceID()
		if err != nil {
			return fmt.Errorf(
				"HierarchyManagementGroup.ModifyPolicyAssignment: "+
					"error getting referenced policy definition resource id for policy assignment %s: %w",
				name,
				err,
			)
		}

		if !mg.hierarchy.alzlib.AssignmentReferencedDefinitionHasParameter(ref, k) {
			return fmt.Errorf(
				"HierarchyManagementGroup.ModifyPolicyAssignment: "+
					"parameter `%s` not found in referenced %s `%s` for policy assignment `%s`",
				k,
				ref.ResourceType.Type,
				ref.Name,
				name,
			)
		}

		mg.policyAssignments[name].Properties.Parameters[k] = v
	}

	if enforcementMode != nil {
		mg.policyAssignments[name].Properties.EnforcementMode = enforcementMode
	}

	if nonComplianceMessages != nil {
		mg.policyAssignments[name].Properties.NonComplianceMessages = nonComplianceMessages
	}

	if resourceSelectors != nil {
		mg.policyAssignments[name].Properties.ResourceSelectors = resourceSelectors
	}

	if overrides != nil {
		mg.policyAssignments[name].Properties.Overrides = overrides
	}

	if identity != nil {
		mg.policyAssignments[name].Identity = identity
	}

	return nil
}

// parseArmFunctionInPolicySetParameter evaluates the ARM expression in a policy set parameter for a
// referenced definition. It builds a map of the parameters in the policy set definition and the
// assignment and evaluates the ARM
// expression using goarmfunctions.
func parseArmFunctionInPolicySetParameter(
	pdRef, paramName string,
	ass *armpolicy.Assignment,
	setDef *armpolicy.SetDefinition,
) (any, error) {
	resultantParams := make(map[string]any)
	for k, v := range setDef.Properties.Parameters {
		resultantParams[k] = v.DefaultValue
	}

	for k, v := range ass.Properties.Parameters {
		resultantParams[k] = v.Value
	}

	var toParse string

	for _, def := range setDef.Properties.PolicyDefinitions {
		if *def.PolicyDefinitionReferenceID != pdRef {
			continue
		}

		p, ok := def.Parameters[paramName]
		if !ok {
			return nil, fmt.Errorf(
				"parseArmFunctionInPolicySetParameter: paramName %s not found in %s",
				paramName,
				*def.PolicyDefinitionReferenceID,
			)
		}

		pStr, ok := p.Value.(string)
		if !ok {
			return nil, fmt.Errorf(
				"parseArmFunctionInPolicySetParameter: paramName %s in %s is not a string",
				paramName,
				*def.PolicyDefinitionReferenceID,
			)
		}

		toParse = pStr
	}

	res, err := goarmfunctions.LexAndParse(context.Background(), toParse, resultantParams, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"parseArmFunctionInPolicySetParameter: error parsing parameter %s in reference %s in set definition %s: %w",
			paramName,
			pdRef,
			*setDef.Name,
			err,
		)
	}

	return res, nil
}

// updatePolicyDefinitions re-writes the policy definition resource IDs for the correct management
// group.
func updatePolicyDefinitions(mg *HierarchyManagementGroup) {
	for k, v := range mg.policyDefinitions {
		v.ID = to.Ptr(fmt.Sprintf(PolicyDefinitionIDFmt, mg.id, k))
	}
}

// These for loops re-write the referenced policy definition resource IDs
// for all policy sets.
// It looks up the policy definition names that are in all archetypes in the Deployment.
// If it is found, the definition reference id is re-written with the correct management group name.
// If it is not found, we assume that it's built-in.
func updatePolicySetDefinitions(
	mg *HierarchyManagementGroup,
	pd2mg map[string]mapset.Set[string],
) error {
	for psdName, psd := range mg.policySetDefinitions {
		psd.ID = to.Ptr(fmt.Sprintf(PolicySetDefinitionIDFmt, mg.id, psdName))

		refs := psd.PolicyDefinitionReferences()
		if refs == nil {
			return fmt.Errorf(
				"updatePolicySetDefinitions: error getting policy definition references for policy set definition %s",
				psdName,
			)
		}

		for _, pdr := range refs {
			pdname, err := assets.NameFromResourceID(*pdr.PolicyDefinitionID)
			if err != nil {
				return fmt.Errorf(
					"updatePolicySetDefinitions: error getting policy definition name from resource id %s: %w",
					*pdr.PolicyDefinitionID,
					err,
				)
			}
			// if the referenced policy definition is custom, we need to update the reference
			if definitionMgs, ok := pd2mg[pdname]; ok {
				updated := false

				for definitionMg := range definitionMgs.Iter() {
					if definitionMg != mg.id && !mg.HasParent(definitionMg) {
						continue
					}

					pdr.PolicyDefinitionID = to.Ptr(fmt.Sprintf(PolicyDefinitionIDFmt, definitionMg, pdname))
					updated = true

					break
				}

				if !updated {
					return fmt.Errorf(
						"updatePolicySetDefinitions: policy set definition %s has a policy definition %s "+
							"that is not in the same hierarchy",
						psdName,
						pdname,
					)
				}
			}
		}
	}

	return nil
}

func updatePolicyAsignments(
	mg *HierarchyManagementGroup,
	pd2mg, psd2mg map[string]mapset.Set[string],
) error {
	// Update resource ids and refs.
	for assignmentName, assignment := range mg.policyAssignments {
		assignment.ID = to.Ptr(fmt.Sprintf(PolicyAssignmentIDFmt, mg.id, assignmentName))
		assignment.Properties.Scope = to.Ptr(fmt.Sprintf(ManagementGroupIDFmt, mg.id))

		if assignment.Location != nil {
			assignment.Location = &mg.location
		}

		// rewrite the referenced policy definition id
		// if the policy definition is in the list.
		pdRes, err := assignment.ReferencedPolicyDefinitionResourceID()
		if err != nil {
			return fmt.Errorf(
				"updatePolicyAssignments: error parsing policy definition id for policy assignment %s: %w",
				assignmentName,
				err,
			)
		}

		switch strings.ToLower(pdRes.ResourceType.Type) {
		case "policydefinitions":
			if deploymentMgs, ok := pd2mg[pdRes.Name]; ok {
				updated := false

				for deploymentMg := range deploymentMgs.Iter() {
					if deploymentMg != mg.id && !mg.HasParent(deploymentMg) {
						continue
					}

					assignment.Properties.PolicyDefinitionID = to.Ptr(
						fmt.Sprintf(PolicyDefinitionIDFmt, deploymentMg, pdRes.Name),
					)
					updated = true

					break
				}

				if !updated {
					return fmt.Errorf(
						"updatePolicyAssignments: policy assignment %s has a policy definition %s that is not in the same hierarchy",
						assignmentName,
						pdRes.Name,
					)
				}
			}
		case "policysetdefinitions":
			if deploymentMg, ok := psd2mg[pdRes.Name]; ok {
				updated := false

				for deploymentMg := range deploymentMg.Iter() {
					if deploymentMg != mg.id && !mg.HasParent(deploymentMg) {
						continue
					}

					assignment.Properties.PolicyDefinitionID = to.Ptr(
						fmt.Sprintf(PolicySetDefinitionIDFmt, deploymentMg, pdRes.Name),
					)
					updated = true

					break
				}

				if !updated {
					return fmt.Errorf(
						"updatePolicyAssignments: policy assignment %s has a policy set definition %s that is not in the same hierarchy",
						assignmentName,
						pdRes.Name,
					)
				}
			}
		default:
			return fmt.Errorf(
				"updatePolicyAssignments: policy assignment %s has invalid referenced definition/set resource type with id: %s",
				assignmentName,
				pdRes.Name,
			)
		}
	}

	return nil
}

func updateRoleDefinitions(alzmg *HierarchyManagementGroup, uniqueRoleDefinitions bool) {
	for _, roledef := range alzmg.roleDefinitions {
		if uniqueRoleDefinitions {
			u := uuidV5(alzmg.id, *roledef.Name)
			roledef.Name = to.Ptr(u.String())
			roledef.Properties.RoleName = to.Ptr(
				fmt.Sprintf("%s (%s)", *roledef.Properties.RoleName, alzmg.id),
			)
		}

		roledef.ID = to.Ptr(fmt.Sprintf(RoleDefinitionIDFmt, alzmg.id, *roledef.Name))

		if len(roledef.Properties.AssignableScopes) == 0 {
			roledef.Properties.AssignableScopes = make([]*string, 1)
		}

		roledef.Properties.AssignableScopes[0] = to.Ptr(alzmg.ResourceID())
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

// MarshalJSON implements the json.Marshaler interface for HierarchyManagementGroup.
func (mg HierarchyManagementGroup) MarshalJSON() ([]byte, error) {
	type marshalHierarchyManagementGroup struct {
		// The ids of the children of the management group.
		Children []string `json:"children,omitempty"`
		// The display name of the management group.
		DisplayName string `json:"display_name,omitempty"`
		// Whether the management group already exists in the hierarchy.
		Exists bool `json:"exists,omitempty"`
		// The name of the management group, forming the last part of the resource id.
		ID string `json:"id,omitempty"`
		// The level of the management group in the hierarchy.
		Level int `json:"level,omitempty"`
		// The default location to use for artifacts in the management group.
		Location string `json:"location,omitempty"`
		// The id of the parent management group.
		Parent *string `json:"parent,omitempty"`
		// The policy assignments in the management group.
		PolicyAssignments map[string]*assets.PolicyAssignment `json:"policy_assignments,omitempty"`
		// The policy definitions in the management group.
		PolicyDefinitions map[string]*assets.PolicyDefinition `json:"policy_definitions,omitempty"`
		// The additional role assignments needed for the policy assignments.
		PolicyRoleAssignments []PolicyRoleAssignment `json:"policy_role_assignments,omitempty"`
		// The policy set definitions in the management group.
		PolicySetDefinitions map[string]*assets.PolicySetDefinition `json:"policy_set_definitions,omitempty"`
		// The role definitions in the management group.
		RoleDefinitions map[string]*assets.RoleDefinition `json:"role_definitions,omitempty"`
	}

	childrenIDs := make([]string, mg.children.Cardinality())
	for i, child := range mg.children.ToSlice() {
		childrenIDs[i] = child.id
	}

	var parentID *string

	switch {
	case mg.parentExternal != nil:
		parentID = mg.parentExternal
	case mg.parent != nil:
		parentID = &mg.parent.id
	}

	tmp := marshalHierarchyManagementGroup{
		Children:              childrenIDs,
		DisplayName:           mg.displayName,
		Exists:                mg.exists,
		ID:                    mg.id,
		Level:                 mg.level,
		Location:              mg.location,
		Parent:                parentID,
		PolicyAssignments:     mg.policyAssignments,
		PolicyDefinitions:     mg.policyDefinitions,
		PolicyRoleAssignments: mg.policyRoleAssignments.ToSlice(),
		PolicySetDefinitions:  mg.policySetDefinitions,
		RoleDefinitions:       mg.roleDefinitions,
	}

	return json.Marshal(tmp) //nolint:wrapcheck
}
