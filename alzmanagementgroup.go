// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
)

// AlzManagementGroup represents an Azure Management Group within a hierarchy, with links to parent and children.
// Note: this is not thread safe, and should not be used concurrently without an external mutex.
type AlzManagementGroup struct {
	name                  string
	displayName           string
	policyDefinitions     map[string]*armpolicy.Definition
	policySetDefinitions  map[string]*armpolicy.SetDefinition
	policyAssignments     map[string]*armpolicy.Assignment
	roleDefinitions       map[string]*armauthorization.RoleDefinition
	policyRoleAssignments mapset.Set[PolicyRoleAssignment]
	children              mapset.Set[*AlzManagementGroup]
	parent                *AlzManagementGroup
	parentExternal        *string
	wkpv                  *WellKnownPolicyValues
}

// PolicyRoleAssignment represents the role assignments that need to be created for a management group.
// Since we could be using system assigned identities, we don't know the principal ID until after the deployment.
// Therefore this data can be used to create the role assignments after the deployment.
type PolicyRoleAssignment struct {
	RoleDefinitionId string
	Scope            string
	AssignmentName   string
}

type PolicyRoleAssignmentSource uint8

const (
	// PolicyRoleAssignmentSource.
	AssignmentScope = PolicyRoleAssignmentSource(iota)
	DefinitionParameterMetadata
	SetDefinitionParameterMetadata
)

// String implements Stringer interface for PolicyRoleAssignmentSource.
func (p PolicyRoleAssignmentSource) String() string {
	return [...]string{"AssignmentScope", "DefinitionParameterMetadata", "SetDefinitionParameterMetadata"}[p]
}

// policyDefinitionRule represents the opinionated rule section of a policy definition.
// This is used to determine the role assignments that need to be created,
// therefore we only care about the `then.details.roleDefinitionIds` field.
type policyDefinitionRule struct {
	Then *struct {
		Details *struct {
			RoleDefinitionIds []string `json:"roleDefinitionIds,omitempty"`
		} `json:"details"`
	} `json:"then"`
}

// GetChildren returns the children of the management group.
func (alzmg *AlzManagementGroup) GetChildren() []*AlzManagementGroup {
	return alzmg.children.ToSlice()
}

// GetParentId returns the ID of the parent management group.
// If the parent is external, this will be preferred.
// If neither are set an empty string is returned (though this should never happen).
func (alzmg *AlzManagementGroup) GetParentId() string {
	if alzmg.parentExternal != nil {
		return *alzmg.parentExternal
	}
	if alzmg.parent != nil {
		return alzmg.parent.name
	}
	return ""
}

// GetParentMg returns parent *AlzManagementGroup.
// If the parent is external, the result will be nil.
func (alzmg *AlzManagementGroup) GetParentMg() *AlzManagementGroup {
	if alzmg.parentExternal != nil {
		return nil
	}
	return alzmg.parent
}

// ParentIsExternal returns a bool value depending on whether the parent MG is external or not.
func (alzmg *AlzManagementGroup) ParentIsExternal() bool {
	if alzmg.parentExternal != nil && *alzmg.parentExternal != "" {
		return true
	}
	return false
}

// ResourceId returns the resource ID of the management group.
func (alzmg *AlzManagementGroup) ResourceId() string {
	return fmt.Sprintf(managementGroupIdFmt, alzmg.name)
}

// GetPolicyAssignmentMap returns a copy of the policy assignments map.
func (alzmg *AlzManagementGroup) GetPolicyAssignmentMap() map[string]armpolicy.Assignment {
	return copyMap[string, armpolicy.Assignment](alzmg.policyAssignments)
}

// GetPolicyDefinitionsMap returns a copy of the policy definitions map.
func (alzmg *AlzManagementGroup) GetPolicyDefinitionsMap() map[string]armpolicy.Definition {
	return copyMap[string, armpolicy.Definition](alzmg.policyDefinitions)
}

// GetPolicySetDefinitionsMap returns a copy of the policy definitions map.
func (alzmg *AlzManagementGroup) GetPolicySetDefinitionsMap() map[string]armpolicy.SetDefinition {
	return copyMap[string, armpolicy.SetDefinition](alzmg.policySetDefinitions)
}

// GetRoleDefinitionsMap returns a copy of the role definitions map.
func (alzmg *AlzManagementGroup) GetRoleDefinitionsMap() map[string]armauthorization.RoleDefinition {
	return copyMap[string, armauthorization.RoleDefinition](alzmg.roleDefinitions)
}

// GetRoleAssignmentsMap returns a copy of the role Assignments map.
// func (alzmg *AlzManagementGroup) GetRoleAssignmentsMap() map[string]armauthorization.RoleAssignment {
// 	return copyMap[string, armauthorization.RoleAssignment](alzmg.roleAssignments)
// }

// GetPolicyRoleAssignmentsMap returns a copy of the additional role assignments slice.
func (alzmg *AlzManagementGroup) GetPolicyRoleAssignments() []PolicyRoleAssignment {
	return alzmg.policyRoleAssignments.ToSlice()
}

// GeneratePolicyAssignmentAdditionalRoleAssignments generates the additional role assignment data needed for the policy assignments
// It should be run once the policy assignments map has been fully populated for a given ALZManagementGroup.
// It will iterate through all policy assignments and generate the additional role assignments for each one,
// storing them in the AdditionalRoleAssignmentsByPolicyAssignment map.
func (alzmg *AlzManagementGroup) GeneratePolicyAssignmentAdditionalRoleAssignments(az *AlzLib) error {
	for paName, pa := range alzmg.policyAssignments {
		// we only care about policy assignments that use an identity
		if pa.Identity == nil || pa.Identity.Type == nil || *pa.Identity.Type == "None" {
			continue
		}

		// get the policy definition name using the resource id
		defId := pa.Properties.PolicyDefinitionID

		switch lastButOneSegment(*defId) {
		case "policyDefinitions":
			// check the definition exists in the AlzLib
			pd, ok := az.policyDefinitions[lastSegment(*defId)]
			if !ok {
				return fmt.Errorf("policy definition %s not found in AlzLib", lastSegment(*defId))
			}
			// get the role definition ids from the policy definition and add to the additional role assignment data
			rids, err := getPolicyDefRoleDefinitionIds(pd.Properties.PolicyRule)
			if err != nil {
				return fmt.Errorf("error getting role definition ids for policy definition %s: %w", *pd.Name, err)
			}
			if len(rids) == 0 {
				return fmt.Errorf("policy definition %s has no role definition ids", *pd.Name)
			}
			for _, rid := range rids {
				alzmg.policyRoleAssignments.Add(PolicyRoleAssignment{
					Scope:            alzmg.GetResourceId(),
					RoleDefinitionId: normalizeRoleDefinitionId(rid),
					AssignmentName:   paName,
				})
			}

			// for each parameter with assignPermissions = true
			// add the additional role assignment data unless the parameter value is empty
			for paramName, paramVal := range pd.Properties.Parameters {
				if paramVal.Metadata == nil || paramVal.Metadata.AssignPermissions == nil || !*paramVal.Metadata.AssignPermissions {
					continue
				}
				paParamVal, err := getPolicyAssignmentParametersValueValue(pa, paramName)
				if err != nil || paParamVal == "" {
					continue
				}
				for _, rid := range rids {
					alzmg.policyRoleAssignments.Add(PolicyRoleAssignment{
						Scope:            paParamVal,
						RoleDefinitionId: normalizeRoleDefinitionId(rid),
						AssignmentName:   paName,
					})
				}
			}

		case "policySetDefinitions":
			psd, ok := az.policySetDefinitions[lastSegment(*defId)]
			if !ok {
				return fmt.Errorf("policy set definition %s not found in AlzLib", lastSegment(*defId))
			}

			// for each policy definition in the policy set definition
			for _, pdref := range psd.Properties.PolicyDefinitions {
				pdName := lastSegment(*pdref.PolicyDefinitionID)
				pd, ok := az.policyDefinitions[pdName]
				if !ok {
					return fmt.Errorf("policy definition %s, referenced by %s not found in AlzLib", pdName, *psd.Name)
				}

				// get the role definition ids from the policy definition and add to the additional role assignment data
				rids, err := getPolicyDefRoleDefinitionIds(pd.Properties.PolicyRule)
				if err != nil {
					return fmt.Errorf("error getting role definition ids for policy definition %s: %w", *pd.Name, err)
				}
				for _, rid := range rids {
					alzmg.policyRoleAssignments.Add(PolicyRoleAssignment{
						Scope:            alzmg.GetResourceId(),
						RoleDefinitionId: normalizeRoleDefinitionId(rid),
						AssignmentName:   paName,
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
					if _, ok := pdref.Parameters[paramName]; !ok {
						return fmt.Errorf("parameter %s not found in policy definition %s", paramName, *pd.Name)
					}
					pdrefParamVal := pdref.Parameters[paramName].Value
					pdrefParamValStr, ok := pdrefParamVal.(string)
					if !ok {
						return fmt.Errorf("parameter %s value in policy definition %s is not a string", paramName, *pd.Name)
					}
					// extract the assignment exposed policy set parameter name from the ARM function used in the policy definition reference
					paParamName, err := extractParameterNameFromArmFunction(pdrefParamValStr)
					if err != nil {
						return err
					}

					// if the parameter in the assignment doesn't exist, skip it
					paParamVal, err := getPolicyAssignmentParametersValueValue(pa, paParamName)
					if err != nil {
						continue
					}
					resid, err := arm.ParseResourceID(paParamVal)
					if err != nil {
						continue
					}
					for _, rid := range rids {
						alzmg.policyRoleAssignments.Add(PolicyRoleAssignment{
							Scope:            resid.String(),
							RoleDefinitionId: normalizeRoleDefinitionId(rid),
							AssignmentName:   paName,
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
func (alzmg *AlzManagementGroup) update(az *AlzLib, papv PolicyAssignmentsParameterValues) error {
	if alzmg.wkpv == nil {
		return fmt.Errorf("well known policy assignment parameter values not set for ALZManagementGroup %s", alzmg.name)
	}

	pd2mg := az.Deployment.policyDefinitionToMg()
	psd2mg := az.Deployment.policySetDefinitionToMg()

	// re-write the policy definition ID property to be the current MG name.
	modifyPolicyDefinitions(alzmg)

	// re-write the policy set definition ID property and go through the referenced definitions
	// and write the definition id if it's custom.
	modifyPolicySetDefinitions(alzmg, pd2mg)

	// re-write the assignableScopes for the role definitions.
	modifyRoleDefinitions(alzmg)

	// re-write the policy assignment ID property to be the current MG name
	// and go through the referenced definitions and write the definition id if it's custom
	// and set the well known parameters.
	// Update well known policy assignment parameters.
	wk := getWellKnownPolicyAssignmentParameterValues(alzmg.wkpv)
	papv = wk.Merge(papv)

	if err := modifyPolicyAssignments(alzmg, pd2mg, psd2mg, papv); err != nil {
		return err
	}

	return nil
}

// ModifyPolicyAssignment modifies an existing policy assignment in the management group.
// It will deep merge the supplied assignments with the existing assignments.
func (alzmg *AlzManagementGroup) ModifyPolicyAssignment(
	name string,
	parameters map[string]*armpolicy.ParameterValuesValue,
	enforcementMode *armpolicy.EnforcementMode,
	nonComplianceMessages []*armpolicy.NonComplianceMessage,
	identity *armpolicy.Identity,
	resourceSelectors []*armpolicy.ResourceSelector,
	overrides []*armpolicy.Override,
) error {
	if _, ok := alzmg.policyAssignments[name]; !ok {
		return fmt.Errorf("policy assignment %s not found in management group %s", name, alzmg.name)
	}

	if alzmg.policyAssignments[name].Properties == nil {
		return fmt.Errorf("properties for policy assignment %s in management group %s is nil", name, alzmg.name)
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

// GetResourceId returns the resource ID for the management group.
func (alzmg *AlzManagementGroup) GetResourceId() string {
	return fmt.Sprintf(managementGroupIdFmt, alzmg.name)
}

// extractParameterNameFromArmFunction extracts the parameter name from an ARM function.
func extractParameterNameFromArmFunction(value string) (string, error) {
	// value is of the form "[parameters('parameterName')]".
	if !strings.HasPrefix(value, "[parameters('") || !strings.HasSuffix(value, "')]") {
		return "", fmt.Errorf("value is not a parameter reference")
	}
	return value[13 : len(value)-3], nil
}

// getPolicyDefRoleDefinitionIds returns the role definition ids referenced in a policy definition
// if they exist.
// We marshall the policyRule as JSON and then unmarshal into a custom type.
func getPolicyDefRoleDefinitionIds(rule any) ([]string, error) {
	j, err := json.Marshal(rule)
	if err != nil {
		return nil, fmt.Errorf("could not marshall policy rule: %w", err)
	}
	r := new(policyDefinitionRule)
	if err := json.Unmarshal(j, r); err != nil {
		// For append policies, the `then.details` field is an array, so we need to handle this case.
		// There are no roleDefinitionIds here anyway, so we can just return an empty slice.
		// This explains why the PolicyRule field if of type any.
		jsonerr := new(json.UnmarshalTypeError)
		if errors.As(err, &jsonerr) {
			if jsonerr.Value == "array" && jsonerr.Field == "then.details" {
				return []string{}, nil
			}
		}
		return nil, fmt.Errorf("could not unmarshall policy rule: %w", err)
	}
	if r.Then.Details == nil || r.Then.Details.RoleDefinitionIds == nil || len(r.Then.Details.RoleDefinitionIds) == 0 {
		return []string{}, nil
	}
	return r.Then.Details.RoleDefinitionIds, nil
}

// getPolicyAssignmentParametersValueValue returns the value of a policy assignment parameter.
// We always expect the value to be a string as it's used in calculating the additional role assignments for
// policy parameters with the assignPermissions metadata set to true.
// Therefore the value should be an ARM resourceId.
func getPolicyAssignmentParametersValueValue(pa *armpolicy.Assignment, paramname string) (string, error) {
	if pa.Properties.Parameters == nil {
		return "", fmt.Errorf("parameters is nil in policy assignment %s", *pa.Name)
	}
	paParamVal, ok := pa.Properties.Parameters[paramname]
	if !ok {
		return "", fmt.Errorf("parameter %s not found in policy assignment %s", paramname, *pa.Name)
	}
	if paParamVal.Value == nil {
		return "", fmt.Errorf("parameter %s value field in policy assignment %s is nil", paramname, *pa.Name)
	}
	paParamValStr, ok := paParamVal.Value.(string)
	if !ok {
		return "", fmt.Errorf("parameter %s value in policy assignment %s is not a string", paramname, *pa.Name)
	}
	return paParamValStr, nil
}

// modifyPolicyDefinitions re-writes the policy definition resource IDs for the correct management group.
func modifyPolicyDefinitions(alzmg *AlzManagementGroup) {
	for k, v := range alzmg.policyDefinitions {
		v.ID = to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, alzmg.name, k))
	}
}

// These for loops re-write the referenced policy definition resource IDs
// for all policy sets.
// It looks up the policy definition names that are in all archetypes in the Deployment.
// If it is found, the definition reference id is re-written with the correct management group name.
// If it is not found, we assume that it's built-in.
func modifyPolicySetDefinitions(alzmg *AlzManagementGroup, pd2mg map[string]string) {
	for k, v := range alzmg.policySetDefinitions {
		v.ID = to.Ptr(fmt.Sprintf(policySetDefinitionIdFmt, alzmg.name, k))
		for _, pd := range v.Properties.PolicyDefinitions {
			pdname := lastSegment(*pd.PolicyDefinitionID)
			if mgname, ok := pd2mg[pdname]; ok {
				pd.PolicyDefinitionID = to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, mgname, pdname))
			}
		}
	}
}

func modifyPolicyAssignments(alzmg *AlzManagementGroup, pd2mg, psd2mg map[string]string, papv PolicyAssignmentsParameterValues) error {
	for assignmentName, params := range papv {
		pa, ok := alzmg.policyAssignments[assignmentName]
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
	for assignmentName, assignment := range alzmg.policyAssignments {
		assignment.ID = to.Ptr(fmt.Sprintf(policyAssignmentIdFmt, alzmg.name, assignmentName))
		assignment.Properties.Scope = to.Ptr(fmt.Sprintf(managementGroupIdFmt, alzmg.name))
		if assignment.Location != nil {
			assignment.Location = alzmg.wkpv.DefaultLocation
		}

		// rewrite the referenced policy definition id
		// if the policy definition is in the list.
		pd := assignment.Properties.PolicyDefinitionID
		switch strings.ToLower(lastButOneSegment(*pd)) {
		case "policydefinitions":
			if mgname, ok := pd2mg[lastSegment(*pd)]; ok {
				assignment.Properties.PolicyDefinitionID = to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, mgname, lastSegment(*pd)))
			}
		case "policysetdefinitions":
			if mgname, ok := psd2mg[lastSegment(*pd)]; ok {
				assignment.Properties.PolicyDefinitionID = to.Ptr(fmt.Sprintf(policySetDefinitionIdFmt, mgname, lastSegment(*pd)))
			}
		default:
			return fmt.Errorf("policy assignment %s has invalid referenced definition/set resource type with id: %s", assignmentName, *pd)
		}
	}
	return nil
}

func modifyRoleDefinitions(alzmg *AlzManagementGroup) {
	for _, roledef := range alzmg.roleDefinitions {
		u := uuidV5(alzmg.name, *roledef.Name)
		roledef.ID = to.Ptr(fmt.Sprintf(roleDefinitionIdFmt, alzmg.name, u))
		if roledef.Properties.AssignableScopes == nil || len(roledef.Properties.AssignableScopes) == 0 {
			roledef.Properties.AssignableScopes = make([]*string, 1)
		}
		roledef.Properties.AssignableScopes[0] = to.Ptr(alzmg.GetResourceId())
	}
}

func newAlzManagementGroup() *AlzManagementGroup {
	return &AlzManagementGroup{
		policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
		policyDefinitions:     make(map[string]*armpolicy.Definition),
		policySetDefinitions:  make(map[string]*armpolicy.SetDefinition),
		policyAssignments:     make(map[string]*armpolicy.Assignment),
		//roleAssignments:       make(map[string]*armauthorization.RoleAssignment),
		roleDefinitions: make(map[string]*armauthorization.RoleDefinition),
	}
}

// copyMap takes a map of pointers and returns a map of values.
func copyMap[E comparable, T any](m map[E]*T) map[E]T {
	m2 := make(map[E]T, len(m))
	for k, v := range m {
		m2[k] = *v
	}
	return m2
}

// normalizeRoleDefinitionId takes a Azure builtin role definition id and returns a normalized id.
func normalizeRoleDefinitionId(id string) string {
	return fmt.Sprintf("/providers/Microsoft.Authorization/roleDefinitions/%s", strings.ToLower((lastSegment(id))))
}
