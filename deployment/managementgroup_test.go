// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePolicyAssignmentAdditionalRoleAssignments(t *testing.T) {
	t.Parallel()
	// create a new AlzLib instance.
	az := alzlib.NewAlzLib(nil)

	// create a new AlzManagementGroup instance.
	mg := &HierarchyManagementGroup{
		policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
		policyDefinitions:     make(map[string]*assets.PolicyDefinition),
		policySetDefinitions:  make(map[string]*assets.PolicySetDefinition),
		policyAssignments:     make(map[string]*assets.PolicyAssignment),
	}

	// create a new policy assignment for the definition.
	paDef := assets.NewPolicyAssignment(armpolicy.Assignment{
		Name: to.Ptr("test-policy-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),

		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"parameter1": {Value: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg"},
				"parameter2": {Value: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg2"},
			},
		},
	})

	// create a new policy assignment for the definition.
	paSetDef := assets.NewPolicyAssignment(armpolicy.Assignment{
		Name: to.Ptr("test-policy-set-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),

		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/test-policy-set-definition"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"setparameter1": {Value: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg"},
				"setparameter2": {Value: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg2"},
			},
		},
	})

	ps := assets.NewPolicySetDefinition(armpolicy.SetDefinition{
		Name: to.Ptr("test-policy-set-definition"),
		Type: to.Ptr("Microsoft.Authorization/policySetDefinitions"),
		Properties: &armpolicy.SetDefinitionProperties{
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"setparameter1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
				"setparameter2": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
			},
			PolicyDefinitions: []*armpolicy.DefinitionReference{
				{
					PolicyDefinitionReferenceID: to.Ptr("test-policy-definition2"),
					PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition2"),
					Parameters: map[string]*armpolicy.ParameterValuesValue{
						"parameter1": {Value: "[parameters('setparameter1')]"},
						"parameter2": {Value: "[parameters('setparameter2')]"},
					},
				},
			},
		},
	})
	// create a new policy definition for direct assignment.
	pd1 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("test-policy-definition"),
		Properties: &armpolicy.DefinitionProperties{
			PolicyRule: map[string]any{
				"If": &map[string]any{
					"AllOf": []any{
						map[string]any{
							"Field": to.Ptr("type"),
							"Equals": []any{
								"Microsoft.Compute/virtualMachines",
							},
						},
					},
				},
				"then": map[string]any{
					"details": map[string]any{
						"roleDefinitionIds": []any{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition"},
					},
				},
			},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"parameter1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(true),
					},
				},
				"parameter2": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(false),
					},
				},
			},
		},
	})

	// create a new policy definition for set assignment.
	pd2 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("test-policy-definition2"),
		Properties: &armpolicy.DefinitionProperties{
			PolicyRule: map[string]any{
				"If": &map[string]any{
					"AllOf": []any{
						map[string]any{
							"Field": to.Ptr("type"),
							"Equals": []any{
								"Microsoft.Compute/virtualMachines",
							},
						},
					},
				},
				"then": map[string]any{
					"details": map[string]any{
						"roleDefinitionIds": []any{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition2"},
					},
				},
			},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"parameter1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(true),
					},
				},
				"parameter2": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(false),
					},
				},
			},
		},
	})

	// add the policy (set) definitions to the arch.
	mg.policyDefinitions[*pd1.Name] = pd1
	mg.policyDefinitions[*pd2.Name] = pd2
	mg.policySetDefinitions[*ps.Name] = ps

	// add the policy assignments to the arch.
	mg.policyAssignments[*paDef.Name] = paDef
	mg.policyAssignments[*paSetDef.Name] = paSetDef

	// add the policy (set) definitions to the alzlib.
	_ = az.AddPolicyDefinitions(pd1, pd2)
	_ = az.AddPolicySetDefinitions(ps)
	_ = az.AddPolicyAssignments(paDef, paSetDef)

	depl := NewHierarchy(az)
	depl.mgs["mg1"] = mg
	mg.hierarchy = depl

	// generate the additional role assignments.
	err := mg.generatePolicyAssignmentAdditionalRoleAssignments()

	// check that there were no errors.
	assert.NoError(t, err)

	// check that the additional role assignments were generated correctly.
	assert.Equal(t, mg.policyRoleAssignments.Cardinality(), 4)

	assert.True(t, mg.policyRoleAssignments.Contains(PolicyRoleAssignment{
		AssignmentName:   *paDef.Name,
		RoleDefinitionId: pd1.Properties.PolicyRule.(map[string]any)["then"].(map[string]any)["details"].(map[string]any)["roleDefinitionIds"].([]any)[0].(string), //nolint:forcetypeassert
		Scope:            mg.ResourceId(),
	}))
	assert.True(t, mg.policyRoleAssignments.Contains(PolicyRoleAssignment{
		AssignmentName:   *paDef.Name,
		RoleDefinitionId: pd1.Properties.PolicyRule.(map[string]any)["then"].(map[string]any)["details"].(map[string]any)["roleDefinitionIds"].([]any)[0].(string), //nolint:forcetypeassert
		Scope:            paDef.Properties.Parameters["parameter1"].Value.(string),                                                                                 //nolint:forcetypeassert
	}))
	assert.True(t, mg.policyRoleAssignments.Contains(PolicyRoleAssignment{
		AssignmentName:   *paSetDef.Name,
		RoleDefinitionId: pd2.Properties.PolicyRule.(map[string]any)["then"].(map[string]any)["details"].(map[string]any)["roleDefinitionIds"].([]any)[0].(string), //nolint:forcetypeassert
		Scope:            mg.ResourceId(),
	}))
	assert.True(t, mg.policyRoleAssignments.Contains(PolicyRoleAssignment{
		AssignmentName:   *paSetDef.Name,
		RoleDefinitionId: pd2.Properties.PolicyRule.(map[string]any)["then"].(map[string]any)["details"].(map[string]any)["roleDefinitionIds"].([]any)[0].(string), //nolint:forcetypeassert
		Scope:            paSetDef.Properties.Parameters["setparameter1"].Value.(string),                                                                           //nolint:forcetypeassert
	}))
}

func TestModifyPolicyAssignments(t *testing.T) {
	t.Parallel()
	// Test with a single policy assignment and policy definition.
	h := NewHierarchy(nil)
	mg := &HierarchyManagementGroup{
		id: "mg1",
		policyAssignments: map[string]*assets.PolicyAssignment{
			"pa1": assets.NewPolicyAssignment(armpolicy.Assignment{
				Name: to.Ptr("pa1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pd1")),
					Scope:              to.Ptr(fmt.Sprintf(ManagementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			}),
		},
		location: "eastus",
	}
	h.mgs["mg1"] = mg
	pd2mg := make(map[string]mapset.Set[string])
	pd2mg["pd1"] = mapset.NewSet("mg1")
	psd2mg := make(map[string]mapset.Set[string])

	err := updatePolicyAsignments(mg, pd2mg, psd2mg)
	require.NoError(t, err)
	expected := fmt.Sprintf(PolicyAssignmentIdFmt, "mg1", "pa1")
	assert.Equal(t, expected, *mg.policyAssignments["pa1"].ID)
	expected = fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *mg.policyAssignments["pa1"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(ManagementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *mg.policyAssignments["pa1"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *mg.policyAssignments["pa1"].Location)

	// Test with multiple policy assignments and policy definitions.
	mg = &HierarchyManagementGroup{
		id: "mg1",
		policyAssignments: map[string]*assets.PolicyAssignment{
			"pa1": assets.NewPolicyAssignment(armpolicy.Assignment{
				Name: to.Ptr("pa1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pd1")),
					Scope:              to.Ptr(fmt.Sprintf(ManagementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			}),
			"pa2": assets.NewPolicyAssignment(armpolicy.Assignment{
				Name: to.Ptr("pa2"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicySetDefinitionIdFmt, "changeme", "psd1")),
					Scope:              to.Ptr(fmt.Sprintf(ManagementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			}),
		},
		location: "eastus",
	}
	pd2mg = make(map[string]mapset.Set[string])
	pd2mg["pd1"] = mapset.NewThreadUnsafeSet("mg1")
	psd2mg = make(map[string]mapset.Set[string])
	psd2mg["psd1"] = mapset.NewThreadUnsafeSet("mg1")
	err = updatePolicyAsignments(mg, pd2mg, psd2mg)
	require.NoError(t, err)
	expected = fmt.Sprintf(PolicyAssignmentIdFmt, "mg1", "pa1")
	assert.Equal(t, expected, *mg.policyAssignments["pa1"].ID)
	expected = fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *mg.policyAssignments["pa1"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(ManagementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *mg.policyAssignments["pa1"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *mg.policyAssignments["pa1"].Location)
	expected = fmt.Sprintf(PolicyAssignmentIdFmt, "mg1", "pa2")
	assert.Equal(t, expected, *mg.policyAssignments["pa2"].ID)
	expected = fmt.Sprintf(PolicySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *mg.policyAssignments["pa2"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(ManagementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *mg.policyAssignments["pa2"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *mg.policyAssignments["pa2"].Location)

	// Test with invalid policy definition id.
	mg = &HierarchyManagementGroup{
		id: "mg1",
		policyAssignments: map[string]*assets.PolicyAssignment{
			"pa1": assets.NewPolicyAssignment(armpolicy.Assignment{
				Name: to.Ptr("policy1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr("invalid"),
					Scope:              to.Ptr(fmt.Sprintf(ManagementGroupIdFmt, "mg1")),
				},
			}),
		},
		location: "changeme",
	}
	pd2mg = make(map[string]mapset.Set[string])
	psd2mg = make(map[string]mapset.Set[string])
	err = updatePolicyAsignments(mg, pd2mg, psd2mg)
	assert.Error(t, err)
	expected = "resource id 'invalid' must start with '/'"
	assert.ErrorContains(t, err, expected)
}

func TestManagementGroupUpdate(t *testing.T) {
	h := NewHierarchy(nil)
	mgRoot := &HierarchyManagementGroup{
		id:                "mgRoot",
		parent:            nil,
		level:             0,
		parentExternal:    to.Ptr("external"),
		location:          "changeme",
		hierarchy:         h,
		policyAssignments: map[string]*assets.PolicyAssignment{},
		policyDefinitions: map[string]*assets.PolicyDefinition{
			"pdRoot01": {
				Definition: armpolicy.Definition{
					Name: to.Ptr("pdRoot01"),
				},
			},
		},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
		roleDefinitions:      map[string]*assets.RoleDefinition{},
	}
	mg1 := &HierarchyManagementGroup{
		id:                "mg1",
		parent:            mgRoot,
		level:             1,
		location:          "changeme",
		hierarchy:         h,
		policyAssignments: map[string]*assets.PolicyAssignment{},
		policyDefinitions: map[string]*assets.PolicyDefinition{
			"pdDeployedTwice": {
				Definition: armpolicy.Definition{
					Name: to.Ptr("pdDeployedTwice"),
				},
			},
		},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
		roleDefinitions:      map[string]*assets.RoleDefinition{},
	}
	mg1a := &HierarchyManagementGroup{
		id:        "mg1a",
		parent:    mg1,
		level:     1,
		location:  "changeme",
		hierarchy: h,
		policyAssignments: map[string]*assets.PolicyAssignment{
			"paAtMg1a": {
				Assignment: armpolicy.Assignment{
					Name: to.Ptr("paAtMg1a"),
					Properties: &armpolicy.AssignmentProperties{
						PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pdDeployedTwice")),
					},
				},
			},
		},
		policyDefinitions: map[string]*assets.PolicyDefinition{},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{
			"psdWithDefAtParent": {
				SetDefinition: armpolicy.SetDefinition{
					Name: to.Ptr("psdWithDefAtParent"),
					Properties: &armpolicy.SetDefinitionProperties{
						PolicyDefinitions: []*armpolicy.DefinitionReference{
							{
								PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pdDeployedTwice")),
							},
						},
					},
				},
			},
		},
		roleDefinitions: map[string]*assets.RoleDefinition{},
	}
	mg2 := &HierarchyManagementGroup{
		id:        "mg2",
		parent:    mgRoot,
		level:     1,
		location:  "changeme",
		hierarchy: h,
		policyAssignments: map[string]*assets.PolicyAssignment{
			"paAtMg2": {
				Assignment: armpolicy.Assignment{
					Name: to.Ptr("paAtMg1a"),
					Properties: &armpolicy.AssignmentProperties{
						PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pdDeployedTwice")),
					},
				},
			},
		},
		policyDefinitions: map[string]*assets.PolicyDefinition{
			"pdDeployedTwice": {
				Definition: armpolicy.Definition{
					Name: to.Ptr("pdDeployedTwice"),
				},
			},
		},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
		roleDefinitions:      map[string]*assets.RoleDefinition{},
	}
	h.mgs["mgRoot"] = mgRoot
	h.mgs["mg1"] = mg1
	h.mgs["mg1a"] = mg1a
	h.mgs["mg2"] = mg2
	mgRoot.children = mapset.NewThreadUnsafeSet(mg1, mg2)
	require.NoError(t, mgRoot.update(true))
	require.NoError(t, mg1.update(true))
	require.NoError(t, mg2.update(true))
	require.NoError(t, mg1a.update(true))

	// Check that the policy assignments reference the correct policy definitions.
	assert.Equal(t, fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pdDeployedTwice"), *mg1a.policyAssignments["paAtMg1a"].Properties.PolicyDefinitionID)
	assert.Equal(t, fmt.Sprintf(PolicyDefinitionIdFmt, "mg2", "pdDeployedTwice"), *mg2.policyAssignments["paAtMg2"].Properties.PolicyDefinitionID)

	// Check that the policy set definitions reference the correct policy definitions.
	assert.Equal(t, fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pdDeployedTwice"), *mg1a.policySetDefinitions["psdWithDefAtParent"].Properties.PolicyDefinitions[0].PolicyDefinitionID)

	// add another root management group
	mgOtherRoot := &HierarchyManagementGroup{
		id:                "mgOtherRoot",
		parent:            nil,
		level:             0,
		parentExternal:    to.Ptr("external"),
		location:          "changeme",
		hierarchy:         h,
		policyAssignments: map[string]*assets.PolicyAssignment{},
		policyDefinitions: map[string]*assets.PolicyDefinition{
			"pdOtherRoot": {
				Definition: armpolicy.Definition{
					Name: to.Ptr("pdOtherRoot"),
				},
			},
		},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
		roleDefinitions:      map[string]*assets.RoleDefinition{},
	}
	h.mgs["mgOtherRoot"] = mgOtherRoot
	require.NoError(t, mgOtherRoot.update(true))

	mg1.policyAssignments["defNotInHierarchy"] = &assets.PolicyAssignment{
		Assignment: armpolicy.Assignment{
			Name: to.Ptr("defNotInHierarchy"),
			Properties: &armpolicy.AssignmentProperties{
				PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pdOtherRoot")),
			},
		},
	}
	assert.ErrorContains(t, mg1.update(true), "policy assignment defNotInHierarchy has a policy definition pdOtherRoot that is not in the same hierarchy")
}

func TestManagementGroupUpdateWithUniqueRoleDefinitions(t *testing.T) {
	h := NewHierarchy(nil)
	mgRoot := &HierarchyManagementGroup{
		id:                   "mgRoot",
		parent:               nil,
		level:                0,
		parentExternal:       to.Ptr("external"),
		location:             "changeme",
		hierarchy:            h,
		policyAssignments:    map[string]*assets.PolicyAssignment{},
		policyDefinitions:    map[string]*assets.PolicyDefinition{},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
		roleDefinitions: map[string]*assets.RoleDefinition{
			"rdRoot01": {
				RoleDefinition: armauthorization.RoleDefinition{
					Name: to.Ptr("8a60c97f-9cb6-536b-b5db-9c997ee1de03"),
					Properties: &armauthorization.RoleDefinitionProperties{
						RoleName:    to.Ptr("[ALZ] Application-Owners"),
						Description: to.Ptr("Contributor role granted for application/operations team at resource group level"),
					},
				},
			},
		},
	}
	mg1 := &HierarchyManagementGroup{
		id:                   "mg1",
		parent:               mgRoot,
		level:                1,
		location:             "changeme",
		hierarchy:            h,
		policyAssignments:    map[string]*assets.PolicyAssignment{},
		policyDefinitions:    map[string]*assets.PolicyDefinition{},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
		roleDefinitions: map[string]*assets.RoleDefinition{
			"rdMg101": {
				RoleDefinition: armauthorization.RoleDefinition{
					Name: to.Ptr("8a60c97f-9cb6-536b-b5db-9c997ee1de03"),
					Properties: &armauthorization.RoleDefinitionProperties{
						RoleName:    to.Ptr("[ALZ] Application-Owners"),
						Description: to.Ptr("Contributor role granted for application/operations team at resource group level"),
					},
				},
			},
		},
	}

	h.mgs["mgRoot"] = mgRoot
	h.mgs["mg1"] = mg1

	mgRoot.children = mapset.NewThreadUnsafeSet(mg1)
	require.NoError(t, mgRoot.update(true))
	require.NoError(t, mg1.update(true))

	// Check that the role definitions are unique
	assert.NotEqual(t, mgRoot.roleDefinitions["rdRoot01"].Name, mg1.roleDefinitions["rdMg101"].Name, "Role definitions should not have the same ID")
	assert.NotEqual(t, mgRoot.roleDefinitions["rdRoot01"].Properties.RoleName, mg1.roleDefinitions["rdMg101"].Properties.RoleName, "Role definitions should not have the same ID")
}

func TestManagementGroupUpdateWithNonUniqueRoleDefinitions(t *testing.T) {
	h := NewHierarchy(nil)
	mgRoot := &HierarchyManagementGroup{
		id:                   "mgRoot",
		parent:               nil,
		level:                0,
		parentExternal:       to.Ptr("external"),
		location:             "changeme",
		hierarchy:            h,
		policyAssignments:    map[string]*assets.PolicyAssignment{},
		policyDefinitions:    map[string]*assets.PolicyDefinition{},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
		roleDefinitions: map[string]*assets.RoleDefinition{
			"rdRoot01": {
				RoleDefinition: armauthorization.RoleDefinition{
					Name: to.Ptr("8a60c97f-9cb6-536b-b5db-9c997ee1de03"),
					Properties: &armauthorization.RoleDefinitionProperties{
						RoleName:    to.Ptr("[ALZ] Application-Owners"),
						Description: to.Ptr("Contributor role granted for application/operations team at resource group level"),
					},
				},
			},
		},
	}
	mg1 := &HierarchyManagementGroup{
		id:                   "mg1",
		parent:               mgRoot,
		level:                1,
		location:             "changeme",
		hierarchy:            h,
		policyAssignments:    map[string]*assets.PolicyAssignment{},
		policyDefinitions:    map[string]*assets.PolicyDefinition{},
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
		roleDefinitions: map[string]*assets.RoleDefinition{
			"rdMg101": {
				RoleDefinition: armauthorization.RoleDefinition{
					Name: to.Ptr("8a60c97f-9cb6-536b-b5db-9c997ee1de03"),
					Properties: &armauthorization.RoleDefinitionProperties{
						RoleName:    to.Ptr("[ALZ] Application-Owners"),
						Description: to.Ptr("Contributor role granted for application/operations team at resource group level"),
					},
				},
			},
		},
	}

	h.mgs["mgRoot"] = mgRoot
	h.mgs["mg1"] = mg1

	mgRoot.children = mapset.NewThreadUnsafeSet(mg1)
	require.NoError(t, mgRoot.update(false))
	require.NoError(t, mg1.update(false))

	// Check that the role definitions are still not unique after update
	assert.Equal(t, mgRoot.roleDefinitions["rdRoot01"].Name, mg1.roleDefinitions["rdMg101"].Name, "Role definitions should not have the same ID after update")
	assert.Equal(t, mgRoot.roleDefinitions["rdRoot01"].Properties.RoleName, mg1.roleDefinitions["rdMg101"].Properties.RoleName, "Role definitions should not have the same ID after update")
}

func TestModifyPolicyDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single policy definition.
	alzmg := &HierarchyManagementGroup{
		id: "mg1",
		policyDefinitions: map[string]*assets.PolicyDefinition{
			"pd1": {},
		},
	}
	updatePolicyDefinitions(alzmg)
	expected := fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policyDefinitions["pd1"].ID)

	// Test with multiple policy definitions.
	alzmg = &HierarchyManagementGroup{
		id: "mg1",
		policyDefinitions: map[string]*assets.PolicyDefinition{
			"pd1": {},
			"pd2": {},
		},
	}
	updatePolicyDefinitions(alzmg)
	expected = fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policyDefinitions["pd1"].ID)
	expected = fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd2")
	assert.Equal(t, expected, *alzmg.policyDefinitions["pd2"].ID)

	// Test with no policy definitions.
	alzmg = &HierarchyManagementGroup{
		id:                "mg1",
		policyDefinitions: map[string]*assets.PolicyDefinition{},
	}
	updatePolicyDefinitions(alzmg)
	assert.Empty(t, alzmg.policyDefinitions)
}

func TestModifyPolicySetDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single policy set definition and a single policy definition.
	alzmg := &HierarchyManagementGroup{
		id: "mg1",
		policySetDefinitions: map[string]*assets.PolicySetDefinition{
			"psd1": assets.NewPolicySetDefinition(armpolicy.SetDefinition{
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pd1")),
						},
					},
				},
			}),
		},
	}
	pd2mg := make(map[string]mapset.Set[string])
	pd2mg["pd1"] = mapset.NewThreadUnsafeSet("mg1")
	err := updatePolicySetDefinitions(alzmg, pd2mg)
	require.NoError(t, err)
	expected := fmt.Sprintf(PolicySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd1"].ID)
	expected = fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd1"].Properties.PolicyDefinitions[0].PolicyDefinitionID)

	// Test with multiple policy set definitions and policy definitions.
	alzmg = &HierarchyManagementGroup{
		id: "mg1",
		policySetDefinitions: map[string]*assets.PolicySetDefinition{
			"psd1": assets.NewPolicySetDefinition(armpolicy.SetDefinition{
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pd1")),
						},
					},
				},
			}),
			"psd2": assets.NewPolicySetDefinition(armpolicy.SetDefinition{
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pd2")),
						},
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(PolicyDefinitionIdFmt, "changeme", "pd3")),
						},
					},
				},
			}),
		},
	}
	pd2mg = make(map[string]mapset.Set[string])
	pd2mg["pd1"] = mapset.NewThreadUnsafeSet("mg1")
	pd2mg["pd2"] = mapset.NewThreadUnsafeSet("mg1")
	pd2mg["pd3"] = mapset.NewThreadUnsafeSet("mg1")

	_ = updatePolicySetDefinitions(alzmg, pd2mg)
	expected = fmt.Sprintf(PolicySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd1"].ID)
	expected = fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd1"].Properties.PolicyDefinitions[0].PolicyDefinitionID)
	expected = fmt.Sprintf(PolicySetDefinitionIdFmt, "mg1", "psd2")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd2"].ID)
	expected = fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd2")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd2"].Properties.PolicyDefinitions[0].PolicyDefinitionID)
	expected = fmt.Sprintf(PolicyDefinitionIdFmt, "mg1", "pd3")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd2"].Properties.PolicyDefinitions[1].PolicyDefinitionID)

	// Test with no policy set definitions or policy definitions.
	alzmg = &HierarchyManagementGroup{
		id:                   "mg1",
		policySetDefinitions: map[string]*assets.PolicySetDefinition{},
	}
	pd2mg = make(map[string]mapset.Set[string])
	_ = updatePolicySetDefinitions(alzmg, pd2mg)
	assert.Empty(t, alzmg.policySetDefinitions)
}

func TestModifyRoleDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single role definition
	alzmg := &HierarchyManagementGroup{
		id: "mg1",
		roleDefinitions: map[string]*assets.RoleDefinition{
			"rd1": assets.NewRoleDefinition(armauthorization.RoleDefinition{
				Name: to.Ptr("role1"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
					RoleName:         to.Ptr("role1"),
				},
			}),
		},
	}
	updateRoleDefinitions(alzmg, true)
	expected := fmt.Sprintf(RoleDefinitionIdFmt, "mg1", uuidV5("mg1", "role1"))
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd1"].ID)
	assert.Len(t, alzmg.roleDefinitions["rd1"].Properties.AssignableScopes, 1)
	expected = fmt.Sprintf(ManagementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd1"].Properties.AssignableScopes[0])

	// Test with multiple role definitions
	alzmg = &HierarchyManagementGroup{
		id: "mg1",
		roleDefinitions: map[string]*assets.RoleDefinition{
			"rd1": assets.NewRoleDefinition(armauthorization.RoleDefinition{
				Name: to.Ptr("role1"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
					RoleName:         to.Ptr("role1"),
				},
			}),
			"rd2": assets.NewRoleDefinition(armauthorization.RoleDefinition{
				Name: to.Ptr("role2"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
					RoleName:         to.Ptr("role2"),
				},
			}),
		},
	}
	updateRoleDefinitions(alzmg, true)
	expected = fmt.Sprintf(RoleDefinitionIdFmt, "mg1", uuidV5("mg1", "role1"))
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd1"].ID)
	assert.Len(t, alzmg.roleDefinitions["rd1"].Properties.AssignableScopes, 1)
	expected = fmt.Sprintf(ManagementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd1"].Properties.AssignableScopes[0])
	assert.Equal(t, fmt.Sprintf(ManagementGroupIdFmt, "mg1"), *alzmg.roleDefinitions["rd1"].Properties.AssignableScopes[0])
	expected = fmt.Sprintf(RoleDefinitionIdFmt, "mg1", uuidV5("mg1", "role2"))
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd2"].ID)
	assert.Len(t, alzmg.roleDefinitions["rd2"].Properties.AssignableScopes, 1)
	assert.Equal(t, fmt.Sprintf(ManagementGroupIdFmt, "mg1"), *alzmg.roleDefinitions["rd2"].Properties.AssignableScopes[0])

	// Test with no role definitions.
	alzmg = &HierarchyManagementGroup{
		id:              "mg1",
		roleDefinitions: map[string]*assets.RoleDefinition{},
	}
	updateRoleDefinitions(alzmg, true)
	assert.Empty(t, alzmg.roleDefinitions)
}

func TestModifyPolicyAssignment(t *testing.T) {
	// Create a new AlzManagementGroup instance
	alzmg := &HierarchyManagementGroup{
		policyAssignments: make(map[string]*assets.PolicyAssignment),
		policyDefinitions: make(map[string]*assets.PolicyDefinition),
	}

	// Add a policy assignment to the management group
	pa := assets.NewPolicyAssignment(armpolicy.Assignment{
		Name: to.Ptr("test-policy-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"parameter1": {Value: "value1"},
			},
		},
	})
	// We need to add the definition too, as ModifyPolicyAssignment checks to see if any parameters are
	// present in the referenced policy (set) definition.
	pd := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("test-policy-definition"),
		Properties: &armpolicy.DefinitionProperties{
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"parameter1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
				"parameter2": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
			},
		},
	})
	az := alzlib.NewAlzLib(nil)
	az.AddPolicyAssignments(pa) //nolint:errcheck
	az.AddPolicyDefinitions(pd) //nolint:errcheck
	h := NewHierarchy(az)
	h.mgs["mg1"] = alzmg
	alzmg.hierarchy = h
	alzmg.policyAssignments["test-policy-assignment"] = pa
	alzmg.policyDefinitions["test-policy-definition"] = pd

	// Define the expected modified policy assignment
	expected := assets.NewPolicyAssignment(armpolicy.Assignment{
		Name: to.Ptr("test-policy-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"parameter1": {Value: "value1"},
				"parameter2": {Value: "value2"},
			},
			EnforcementMode:       to.Ptr(armpolicy.EnforcementModeDefault),
			NonComplianceMessages: []*armpolicy.NonComplianceMessage{},
			ResourceSelectors: []*armpolicy.ResourceSelector{
				{
					Name: to.Ptr("resourceSelector1"),
					Selectors: []*armpolicy.Selector{
						{
							Kind: to.Ptr(armpolicy.SelectorKindResourceLocation),
							In:   to.SliceOfPtrs([]string{"eastus"}...),
						},
					},
				},
			},
			Overrides: []*armpolicy.Override{},
		},
		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
	})

	// Call the ModifyPolicyAssignment function
	err := alzmg.ModifyPolicyAssignment(
		"test-policy-assignment",
		map[string]*armpolicy.ParameterValuesValue{
			"parameter2": {Value: "value2"},
		},
		to.Ptr(armpolicy.EnforcementModeDefault),
		[]*armpolicy.NonComplianceMessage{},
		&armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		[]*armpolicy.ResourceSelector{
			{
				Name: to.Ptr("resourceSelector1"),
				Selectors: []*armpolicy.Selector{
					{
						Kind: to.Ptr(armpolicy.SelectorKindResourceLocation),
						In:   to.SliceOfPtrs([]string{"eastus"}...),
					},
				},
			},
		},
		[]*armpolicy.Override{},
	)

	// Check for errors
	assert.NoError(t, err)

	// Check if the policy assignment was modified correctly
	assert.Equal(t, expected, alzmg.policyAssignments["test-policy-assignment"])
}

func TestHasParent(t *testing.T) {
	mg1 := &HierarchyManagementGroup{
		id:             "mg1",
		parent:         nil,
		parentExternal: nil,
	}
	mg2 := &HierarchyManagementGroup{
		id:             "mg2",
		parent:         mg1,
		parentExternal: nil,
	}
	mg3 := &HierarchyManagementGroup{
		id:             "mg3",
		parent:         mg2,
		parentExternal: nil,
	}
	mg4 := &HierarchyManagementGroup{
		id:             "mg4",
		parent:         nil,
		parentExternal: to.Ptr("external"),
	}

	tests := []struct {
		name     string
		mg       *HierarchyManagementGroup
		parentID string
		want     bool
	}{
		{
			name:     "HasParent with direct parent",
			mg:       mg2,
			parentID: "mg1",
			want:     true,
		},
		{
			name:     "HasParent with indirect parent",
			mg:       mg3,
			parentID: "mg1",
			want:     true,
		},
		{
			name:     "HasParent with non-existent parent",
			mg:       mg3,
			parentID: "mg5",
			want:     false,
		},
		{
			name:     "HasParent with external parent",
			mg:       mg4,
			parentID: "external",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mg.HasParent(tt.parentID)
			if got != tt.want {
				t.Errorf("HasParent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseArmFunctionInPolicySetParameter(t *testing.T) {
	set := deployPrivateDnsZonesPolicySetDefinition()
	ass := deployPrivateDnsZonesPolicyAssignment()
	const subId = "00000000-0000-0000-0000-000000000001"
	const rgName = "myRg"
	const location = "uksouth"
	const locationShort = "uks"
	location2short := map[string]string{location: locationShort}
	ass.Properties.Parameters["dnsZoneSubscriptionId"] = &armpolicy.ParameterValuesValue{Value: "00000000-0000-0000-0000-000000000001"}
	ass.Properties.Parameters["dnsZoneResourceGroupName"] = &armpolicy.ParameterValuesValue{Value: "myRg"}
	ass.Properties.Parameters["dnsZoneRegion"] = &armpolicy.ParameterValuesValue{Value: location}
	tcs := []struct {
		policyDefinitionRef string
		parameterName       string
		dnsZone             string
	}{
		{
			"DINE-Private-DNS-Azure-File-Sync",
			"privateDnsZoneId",
			"privatelink.afs.azure.net",
		},
		{
			"DINE-Private-DNS-Azure-Automation-Webhook",
			"privateDnsZoneId",
			"privatelink.azure-automation.net",
		},
		{
			"DINE-Private-DNS-Azure-Automation-DSCHybrid",
			"privateDnsZoneId",
			"privatelink.azure-automation.net",
		},
		{
			"DINE-Private-DNS-Azure-Cosmos-SQL",
			"privateDnsZoneId",
			"privatelink.documents.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Cosmos-MongoDB",
			"privateDnsZoneId",
			"privatelink.mongo.cosmos.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Cosmos-Cassandra",
			"privateDnsZoneId",
			"privatelink.cassandra.cosmos.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Cosmos-Gremlin",
			"privateDnsZoneId",
			"privatelink.gremlin.cosmos.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Cosmos-Table",
			"privateDnsZoneId",
			"privatelink.table.cosmos.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-DataFactory",
			"privateDnsZoneId",
			"privatelink.datafactory.azure.net",
		},
		{
			"DINE-Private-DNS-Azure-DataFactory-Portal",
			"privateDnsZoneId",
			"privatelink.adf.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Databricks-UI-Api",
			"privateDnsZoneId",
			"privatelink.azuredatabricks.net",
		},
		{
			"DINE-Private-DNS-Azure-Databricks-Browser-AuthN",
			"privateDnsZoneId",
			"privatelink.azuredatabricks.net",
		},
		{
			"DINE-Private-DNS-Azure-HDInsight",
			"privateDnsZoneId",
			"privatelink.azurehdinsight.net",
		},
		{
			"DINE-Private-DNS-Azure-Migrate",
			"privateDnsZoneId",
			"privatelink.prod.migration.windowsazure.com",
		},
		{
			"DINE-Private-DNS-Azure-Storage-Blob",
			"privateDnsZoneId",
			"privatelink.blob.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-Blob-Sec",
			"privateDnsZoneId",
			"privatelink.blob.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-Queue",
			"privateDnsZoneId",
			"privatelink.queue.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-Queue-Sec",
			"privateDnsZoneId",
			"privatelink.queue.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-File",
			"privateDnsZoneId",
			"privatelink.file.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-StaticWeb",
			"privateDnsZoneId",
			"privatelink.web.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-StaticWeb-Sec",
			"privateDnsZoneId",
			"privatelink.web.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-DFS",
			"privateDnsZoneId",
			"privatelink.dfs.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-DFS-Sec",
			"privateDnsZoneId",
			"privatelink.dfs.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Synapse-SQL",
			"privateDnsZoneId",
			"privatelink.sql.azuresynapse.net",
		},
		{
			"DINE-Private-DNS-Azure-Synapse-SQL-OnDemand",
			"privateDnsZoneId",
			"privatelink.sql.azuresynapse.net",
		},
		{
			"DINE-Private-DNS-Azure-Synapse-Dev",
			"privateDnsZoneId",
			"privatelink.dev.azuresynapse.net",
		},
		{
			"DINE-Private-DNS-Azure-MediaServices-Key",
			"privateDnsZoneId",
			"privatelink.media.azure.net",
		},
		{
			"DINE-Private-DNS-Azure-MediaServices-Live",
			"privateDnsZoneId",
			"privatelink.media.azure.net",
		},
		{
			"DINE-Private-DNS-Azure-MediaServices-Stream",
			"privateDnsZoneId",
			"privatelink.media.azure.net",
		},
		{
			"DINE-Private-DNS-Azure-Monitor",
			"privateDnsZoneId2",
			"privatelink.oms.opinsights.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Monitor",
			"privateDnsZoneId3",
			"privatelink.ods.opinsights.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Monitor",
			"privateDnsZoneId4",
			"privatelink.agentsvc.azure-automation.net",
		},
		{
			"DINE-Private-DNS-Azure-Monitor",
			"privateDnsZoneId5",
			"privatelink.blob.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Monitor",
			"privateDnsZoneId1",
			"privatelink.monitor.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Web",
			"privateDnsZoneId",
			"privatelink.webpubsub.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Batch",
			"privateDnsZoneId",
			"privatelink.batch.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-App",
			"privateDnsZoneId",
			"privatelink.azconfig.io",
		},
		{
			"DINE-Private-DNS-Azure-Site-Recovery",
			"privateDnsZoneId",
			"privatelink.siterecovery.windowsazure.com",
		},
		{
			"DINE-Private-DNS-Azure-IoT",
			"privateDnsZoneId",
			"privatelink.azure-devices-provisioning.net",
		},
		{
			"DINE-Private-DNS-Azure-KeyVault",
			"privateDnsZoneId",
			"privatelink.vaultcore.azure.net",
		},
		{
			"DINE-Private-DNS-Azure-SignalR",
			"privateDnsZoneId",
			"privatelink.service.signalr.net",
		},
		{
			"DINE-Private-DNS-Azure-AppServices",
			"privateDnsZoneId",
			"privatelink.azurewebsites.net",
		},
		{
			"DINE-Private-DNS-Azure-EventGridTopics",
			"privateDnsZoneId",
			"privatelink.eventgrid.azure.net",
		},
		{
			"DINE-Private-DNS-Azure-DiskAccess",
			"privateDnsZoneId",
			"privatelink.blob.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-CognitiveServices",
			"privateDnsZoneId",
			"privatelink.cognitiveservices.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-IoTHubs",
			"privateDnsZoneId",
			"privatelink.azure-devices.net",
		},
		{
			"DINE-Private-DNS-Azure-EventGridDomains",
			"privateDnsZoneId",
			"privatelink.eventgrid.azure.net",
		},
		{
			"DINE-Private-DNS-Azure-RedisCache",
			"privateDnsZoneId",
			"privatelink.redis.cache.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-ACR",
			"privateDnsZoneId",
			"privatelink.azurecr.io",
		},
		{
			"DINE-Private-DNS-Azure-EventHubNamespace",
			"privateDnsZoneId",
			"privatelink.servicebus.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-MachineLearningWorkspace",
			"privateDnsZoneId",
			"privatelink.api.azureml.ms",
		},
		{
			"DINE-Private-DNS-Azure-ServiceBusNamespace",
			"privateDnsZoneId",
			"privatelink.servicebus.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-CognitiveSearch",
			"privateDnsZoneId",
			"privatelink.search.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-BotService",
			"privateDnsZoneId",
			"privatelink.directline.botframework.com",
		},
		{
			"DINE-Private-DNS-Azure-ManagedGrafanaWorkspace",
			"privateDnsZoneId",
			"privatelink.grafana.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-VirtualDesktopHostpool",
			"privateDnsZoneId",
			"privatelink.wvd.microsoft.com",
		},
		{
			"DINE-Private-DNS-Azure-VirtualDesktopWorkspace",
			"privateDnsZoneId",
			"privatelink.wvd.microsoft.com",
		},
		{
			"DINE-Private-DNS-Azure-IoTDeviceupdate",
			"privateDnsZoneId",
			"privatelink.azure-devices.net",
		},
		{
			"DINE-Private-DNS-Azure-Arc",
			"privateDnsZoneIDForGuestConfiguration",
			"privatelink.guestconfiguration.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Arc",
			"privateDnsZoneIDForHybridResourceProvider",
			"privatelink.his.arc.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-Arc",
			"privateDnsZoneIDForKubernetesConfiguration",
			"privatelink.dp.kubernetesconfiguration.azure.com",
		},
		{
			"DINE-Private-DNS-Azure-IoTCentral",
			"privateDnsZoneId",
			"privatelink.azureiotcentral.com",
		},
		{
			"DINE-Private-DNS-Azure-Storage-Table",
			"privateDnsZoneId",
			"privatelink.table.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Storage-Table-Secondary",
			"privateDnsZoneId",
			"privatelink.table.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Site-Recovery-Backup",
			"privateDnsZone-Blob",
			"privatelink.blob.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Site-Recovery-Backup",
			"privateDnsZone-Queue",
			"privatelink.queue.core.windows.net",
		},
		{
			"DINE-Private-DNS-Azure-Site-Recovery-Backup",
			"privateDnsZone-Backup",
			fmt.Sprintf("privatelink.%s.backup.windowsazure.com", location2short[location]),
		},
	}
	for _, tc := range tcs {
		result, err := parseArmFunctionInPolicySetParameter(tc.policyDefinitionRef, tc.parameterName, ass, set)
		assert.NoErrorf(t, err, "error in %s with param %s", tc.policyDefinitionRef, tc.parameterName)
		if err != nil {
			t.Logf("ERROR - %s", err.Error())
			continue
		}
		expected := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/privateDnsZones/%s", subId, strings.ToLower(rgName), tc.dnsZone)
		assert.Equal(t, expected, result)
	}
}

func deployPrivateDnsZonesPolicySetDefinition() *armpolicy.SetDefinition {
	source := `{
  "name": "Deploy-Private-DNS-Zones",
  "properties": {
    "description": "This policy initiative is a group of policies that ensures private endpoints to Azure PaaS services are integrated with Azure Private DNS zones",
    "displayName": "Configure Azure PaaS services to use private DNS zones",
    "metadata": {
      "alzCloudEnvironments": [
        "AzureCloud"
      ],
      "category": "Network",
      "source": "https://github.com/Azure/Enterprise-Scale/",
      "version": "2.3.0"
    },
    "parameters": {
      "azureAcrPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureAcrPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureAppPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureAppPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureAppServicesPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureAppServicesPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureArcGuestconfigurationPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureArcGuestconfigurationPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureArcHybridResourceProviderPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureArcHybridResourceProviderPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureArcKubernetesConfigurationPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureArcKubernetesConfigurationPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureAsrPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureAsrPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureAutomationDSCHybridPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureAutomationDSCHybridPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureAutomationWebhookPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureAutomationWebhookPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureBatchPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureBatchPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureBotServicePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureBotServicePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureCognitiveSearchPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureCognitiveSearchPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureCognitiveServicesPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureCognitiveServicesPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureCosmosCassandraPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureCosmosCassandraPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureCosmosGremlinPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureCosmosGremlinPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureCosmosMongoPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureCosmosMongoPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureCosmosSQLPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureCosmosSQLPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureCosmosTablePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureCosmosTablePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureDataFactoryPortalPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureDataFactoryPortalPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureDataFactoryPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureDataFactoryPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureDatabricksPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureDatabricksPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureDiskAccessPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureDiskAccessPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureEventGridDomainsPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureEventGridDomainsPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureEventGridTopicsPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureEventGridTopicsPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureEventHubNamespacePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureEventHubNamespacePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureFilePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureFilePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureHDInsightPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureHDInsightPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureIotCentralPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureIotCentralPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureIotDeviceupdatePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureIotDeviceupdatePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureIotHubsPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureIotHubsPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureIotPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureIotPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureKeyVaultPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureKeyVaultPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMachineLearningWorkspacePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMachineLearningWorkspacePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMachineLearningWorkspaceSecondPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMachineLearningWorkspaceSecondPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureManagedGrafanaWorkspacePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureManagedGrafanaWorkspacePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMediaServicesKeyPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMediaServicesKeyPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMediaServicesLivePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMediaServicesLivePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMediaServicesStreamPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMediaServicesStreamPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMigratePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMigratePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMonitorPrivateDnsZoneId1": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMonitorPrivateDnsZoneId1",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMonitorPrivateDnsZoneId2": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMonitorPrivateDnsZoneId2",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMonitorPrivateDnsZoneId3": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMonitorPrivateDnsZoneId3",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMonitorPrivateDnsZoneId4": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMonitorPrivateDnsZoneId4",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureMonitorPrivateDnsZoneId5": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureMonitorPrivateDnsZoneId5",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureRedisCachePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureRedisCachePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureServiceBusNamespacePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureServiceBusNamespacePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureSignalRPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureSignalRPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureSiteRecoveryBackupPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureSiteRecoveryBackupPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureSiteRecoveryBlobPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureSiteRecoveryBlobPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureSiteRecoveryQueuePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureSiteRecoveryQueuePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageBlobPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageBlobPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageBlobSecPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageBlobSecPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageDFSPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageDFSPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageDFSSecPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageDFSSecPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageFilePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageFilePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageQueuePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageQueuePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageQueueSecPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageQueueSecPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageStaticWebPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageStaticWebPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageStaticWebSecPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageStaticWebSecPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageTablePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageTablePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureStorageTableSecondaryPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureStorageTableSecondaryPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureSynapseDevPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureSynapseDevPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureSynapseSQLODPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureSynapseSQLODPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureSynapseSQLPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureSynapseSQLPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureVirtualDesktopHostpoolPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureVirtualDesktopHostpoolPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureVirtualDesktopWorkspacePrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureVirtualDesktopWorkspacePrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "azureWebPrivateDnsZoneId": {
        "defaultValue": "",
        "metadata": {
          "description": "Private DNS Zone Identifier",
          "displayName": "azureWebPrivateDnsZoneId",
          "strongType": "Microsoft.Network/privateDnsZones"
        },
        "type": "string"
      },
      "dnsZoneNames": {
        "defaultValue": {
          "azureAcrDataPrivateDnsZoneId": "{regionName}.data.privatelink.azurecr.io",
          "azureAcrPrivateDnsZoneId": "privatelink.azurecr.io",
          "azureAppPrivateDnsZoneId": "privatelink.azconfig.io",
          "azureAppServicesPrivateDnsZoneId": "privatelink.azurewebsites.net",
          "azureArcGuestconfigurationPrivateDnsZoneId": "privatelink.guestconfiguration.azure.com",
          "azureArcHybridResourceProviderPrivateDnsZoneId": "privatelink.his.arc.azure.com",
          "azureArcKubernetesConfigurationPrivateDnsZoneId": "privatelink.dp.kubernetesconfiguration.azure.com",
          "azureAsrPrivateDnsZoneId": "privatelink.siterecovery.windowsazure.com",
          "azureAutomationDSCHybridPrivateDnsZoneId": "privatelink.azure-automation.net",
          "azureAutomationWebhookPrivateDnsZoneId": "privatelink.azure-automation.net",
          "azureBatchPrivateDnsZoneId": "privatelink.batch.azure.com",
          "azureBotServicePrivateDnsZoneId": "privatelink.directline.botframework.com",
          "azureCognitiveSearchPrivateDnsZoneId": "privatelink.search.windows.net",
          "azureCognitiveServicesPrivateDnsZoneId": "privatelink.cognitiveservices.azure.com",
          "azureCosmosCassandraPrivateDnsZoneId": "privatelink.cassandra.cosmos.azure.com",
          "azureCosmosGremlinPrivateDnsZoneId": "privatelink.gremlin.cosmos.azure.com",
          "azureCosmosMongoPrivateDnsZoneId": "privatelink.mongo.cosmos.azure.com",
          "azureCosmosSQLPrivateDnsZoneId": "privatelink.documents.azure.com",
          "azureCosmosTablePrivateDnsZoneId": "privatelink.table.cosmos.azure.com",
          "azureDataExplorerPrivateDnsZoneId": "privatelink.{regionName}.kusto.windows.net",
          "azureDataFactoryPortalPrivateDnsZoneId": "privatelink.adf.azure.com",
          "azureDataFactoryPrivateDnsZoneId": "privatelink.datafactory.azure.net",
          "azureDatabricksPrivateDnsZoneId": "privatelink.azuredatabricks.net",
          "azureDiskAccessPrivateDnsZoneId": "privatelink.blob.core.windows.net",
          "azureEventGridDomainsPrivateDnsZoneId": "privatelink.eventgrid.azure.net",
          "azureEventGridTopicsPrivateDnsZoneId": "privatelink.eventgrid.azure.net",
          "azureEventHubNamespacePrivateDnsZoneId": "privatelink.servicebus.windows.net",
          "azureFilePrivateDnsZoneId": "privatelink.afs.azure.net",
          "azureHDInsightPrivateDnsZoneId": "privatelink.azurehdinsight.net",
          "azureIotCentralPrivateDnsZoneId": "privatelink.azureiotcentral.com",
          "azureIotDeviceupdatePrivateDnsZoneId": "privatelink.azure-devices.net",
          "azureIotHubsPrivateDnsZoneId": "privatelink.azure-devices.net",
          "azureIotPrivateDnsZoneId": "privatelink.azure-devices-provisioning.net",
          "azureKeyVaultPrivateDnsZoneId": "privatelink.vaultcore.azure.net",
          "azureKubernetesManagementPrivateDnsZoneId": "privatelink.{regionName}.azmk8s.io",
          "azureMachineLearningWorkspacePrivateDnsZoneId": "privatelink.api.azureml.ms",
          "azureMachineLearningWorkspaceSecondPrivateDnsZoneId": "privatelink.notebooks.azure.net",
          "azureManagedGrafanaWorkspacePrivateDnsZoneId": "privatelink.grafana.azure.com",
          "azureMediaServicesKeyPrivateDnsZoneId": "privatelink.media.azure.net",
          "azureMediaServicesLivePrivateDnsZoneId": "privatelink.media.azure.net",
          "azureMediaServicesStreamPrivateDnsZoneId": "privatelink.media.azure.net",
          "azureMigratePrivateDnsZoneId": "privatelink.prod.migration.windowsazure.com",
          "azureMonitorPrivateDnsZoneId1": "privatelink.monitor.azure.com",
          "azureMonitorPrivateDnsZoneId2": "privatelink.oms.opinsights.azure.com",
          "azureMonitorPrivateDnsZoneId3": "privatelink.ods.opinsights.azure.com",
          "azureMonitorPrivateDnsZoneId4": "privatelink.agentsvc.azure-automation.net",
          "azureMonitorPrivateDnsZoneId5": "privatelink.blob.core.windows.net",
          "azureRedisCachePrivateDnsZoneId": "privatelink.redis.cache.windows.net",
          "azureServiceBusNamespacePrivateDnsZoneId": "privatelink.servicebus.windows.net",
          "azureSignalRPrivateDnsZoneId": "privatelink.service.signalr.net",
          "azureSiteRecoveryBackupPrivateDnsZoneId": "privatelink.{regionCode}.backup.windowsazure.com",
          "azureSiteRecoveryBlobPrivateDnsZoneId": "privatelink.blob.core.windows.net",
          "azureSiteRecoveryQueuePrivateDnsZoneId": "privatelink.queue.core.windows.net",
          "azureStorageBlobPrivateDnsZoneId": "privatelink.blob.core.windows.net",
          "azureStorageBlobSecPrivateDnsZoneId": "privatelink.blob.core.windows.net",
          "azureStorageDFSPrivateDnsZoneId": "privatelink.dfs.core.windows.net",
          "azureStorageDFSSecPrivateDnsZoneId": "privatelink.dfs.core.windows.net",
          "azureStorageFilePrivateDnsZoneId": "privatelink.file.core.windows.net",
          "azureStorageQueuePrivateDnsZoneId": "privatelink.queue.core.windows.net",
          "azureStorageQueueSecPrivateDnsZoneId": "privatelink.queue.core.windows.net",
          "azureStorageStaticWebPrivateDnsZoneId": "privatelink.web.core.windows.net",
          "azureStorageStaticWebSecPrivateDnsZoneId": "privatelink.web.core.windows.net",
          "azureStorageTablePrivateDnsZoneId": "privatelink.table.core.windows.net",
          "azureStorageTableSecondaryPrivateDnsZoneId": "privatelink.table.core.windows.net",
          "azureSynapseDevPrivateDnsZoneId": "privatelink.dev.azuresynapse.net",
          "azureSynapseSQLODPrivateDnsZoneId": "privatelink.sql.azuresynapse.net",
          "azureSynapseSQLPrivateDnsZoneId": "privatelink.sql.azuresynapse.net",
          "azureVirtualDesktopHostpoolPrivateDnsZoneId": "privatelink.wvd.microsoft.com",
          "azureVirtualDesktopWorkspacePrivateDnsZoneId": "privatelink.wvd.microsoft.com",
          "azureWebPrivateDnsZoneId": "privatelink.webpubsub.azure.com"
        },
        "metadata": {
          "description": "The list of private DNS zone names to be used for the Azure PaaS services.",
          "displayName": "DNS Zone Names"
        },
        "type": "object"
      },
      "dnsZoneRegion": {
        "defaultValue": "changeme",
        "metadata": {
          "description": "The region where the private DNS zones are deployed. If this is specified, it will override any individual private DNS zone resource ids specified.",
          "displayName": "Region"
        },
        "type": "string"
      },
      "dnsZoneResourceGroupName": {
        "defaultValue": "",
        "metadata": {
          "description": "The resource group where the private DNS zones are deployed. If this is specified, it will override any individual private DNS zone resource ids specified.",
          "displayName": "Resource Group Name"
        },
        "type": "string"
      },
      "dnsZoneResourceType": {
        "defaultValue": "Microsoft.Network/privateDnsZones",
        "metadata": {
          "description": "The resource type where the private DNS zones are deployed. If this is specified, it will override any individual private DNS zone resource ids specified.",
          "displayName": "Resource Type"
        },
        "type": "string"
      },
      "dnsZoneSubscriptionId": {
        "defaultValue": "",
        "metadata": {
          "description": "The subscription id where the private DNS zones are deployed. If this is specified, it will override any individual private DNS zone resource ids specified.",
          "displayName": "Subscription Id"
        },
        "type": "string"
      },
      "dnzZoneRegionShortNames": {
        "defaultValue": {
          "australiacentral": "acl",
          "australiacentral2": "acl2",
          "australiaeast": "ae",
          "australiasoutheast": "ase",
          "brazilsouth": "brs",
          "brazilsoutheast": "bse",
          "canadacentral": "cnc",
          "canadaeast": "cne",
          "centralindia": "inc",
          "centralus": "cus",
          "centraluseuap": "ccy",
          "changeme": "changeme",
          "chilecentral": "clc",
          "eastasia": "ea",
          "eastus": "eus",
          "eastus2": "eus2",
          "eastus2euap": "ecy",
          "francecentral": "frc",
          "francesouth": "frs",
          "germanynorth": "gn",
          "germanywestcentral": "gwc",
          "israelcentral": "ilc",
          "italynorth": "itn",
          "japaneast": "jpe",
          "japanwest": "jpw",
          "koreacentral": "krc",
          "koreasouth": "krs",
          "malaysiasouth": "mys",
          "malaysiawest": "myw",
          "mexicocentral": "mxc",
          "newzealandnorth": "nzn",
          "northcentralus": "ncus",
          "northeurope": "ne",
          "norwayeast": "nwe",
          "norwaywest": "nww",
          "polandcentral": "plc",
          "qatarcentral": "qac",
          "southafricanorth": "san",
          "southafricawest": "saw",
          "southcentralus": "scus",
          "southeastasia": "sea",
          "southindia": "ins",
          "spaincentral": "spc",
          "swedencentral": "sdc",
          "swedensouth": "sds",
          "switzerlandnorth": "szn",
          "switzerlandwest": "szw",
          "taiwannorth": "twn",
          "uaecentral": "uac",
          "uaenorth": "uan",
          "uksouth": "uks",
          "ukwest": "ukw",
          "westcentralus": "wcus",
          "westeurope": "we",
          "westindia": "inw",
          "westus": "wus",
          "westus2": "wus2",
          "westus3": "wus3"
        },
        "metadata": {
          "description": "Mapping of region to private DNS zone resource id. If the region is not specified, the default private DNS zone resource id will be used.",
          "displayName": "Region Short Name Mapping"
        },
        "type": "object"
      },
      "effect": {
        "allowedValues": [
          "DeployIfNotExists",
          "Disabled"
        ],
        "defaultValue": "DeployIfNotExists",
        "metadata": {
          "description": "Enable or disable the execution of the policy",
          "displayName": "Effect"
        },
        "type": "string"
      },
      "effect1": {
        "allowedValues": [
          "deployIfNotExists",
          "Disabled"
        ],
        "defaultValue": "deployIfNotExists",
        "metadata": {
          "description": "Enable or disable the execution of the policy",
          "displayName": "Effect"
        },
        "type": "string"
      }
    },
    "policyDefinitions": [
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureFilePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureFilePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/06695360-db88-47f6-b976-7500d4297475",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-File-Sync"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureAutomationWebhookPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureAutomationWebhookPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "Webhook"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/6dd01e4f-1be1-4e80-9d0b-d109e04cb064",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Automation-Webhook"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureAutomationDSCHybridPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureAutomationDSCHybridPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "DSCAndHybridWorker"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/6dd01e4f-1be1-4e80-9d0b-d109e04cb064",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Automation-DSCHybrid"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureCosmosSQLPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureCosmosSQLPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "SQL"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/a63cc0bd-cda4-4178-b705-37dc439d3e0f",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Cosmos-SQL"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureCosmosMongoPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureCosmosMongoPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "MongoDB"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/a63cc0bd-cda4-4178-b705-37dc439d3e0f",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Cosmos-MongoDB"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureCosmosCassandraPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureCosmosCassandraPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "Cassandra"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/a63cc0bd-cda4-4178-b705-37dc439d3e0f",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Cosmos-Cassandra"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureCosmosGremlinPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureCosmosGremlinPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "Gremlin"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/a63cc0bd-cda4-4178-b705-37dc439d3e0f",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Cosmos-Gremlin"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureCosmosTablePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureCosmosTablePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "Table"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/a63cc0bd-cda4-4178-b705-37dc439d3e0f",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Cosmos-Table"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "listOfGroupIds": {
            "value": [
              "dataFactory"
            ]
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureDataFactoryPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureDataFactoryPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/86cd96e1-1745-420d-94d4-d3f2fe415aa4",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-DataFactory"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "listOfGroupIds": {
            "value": [
              "portal"
            ]
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureDataFactoryPortalPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureDataFactoryPortalPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/86cd96e1-1745-420d-94d4-d3f2fe415aa4",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-DataFactory-Portal"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "groupId": {
            "value": "databricks_ui_api"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureDatabricksPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureDatabricksPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0eddd7f3-3d9b-4927-a07a-806e8ac9486c",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Databricks-UI-Api"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "groupId": {
            "value": "browser_authentication"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureDatabricksPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureDatabricksPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0eddd7f3-3d9b-4927-a07a-806e8ac9486c",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Databricks-Browser-AuthN"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "groupId": {
            "value": "cluster"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureHDInsightPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureHDInsightPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/43d6e3bd-fc6a-4b44-8b4d-2151d8736a11",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-HDInsight"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMigratePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMigratePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/7590a335-57cf-4c95-babd-ecbc8fafeb1f",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Migrate"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageBlobPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageBlobPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/75973700-529f-4de2-b794-fb9b6781b6b0",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-Blob"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageBlobSecPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageBlobSecPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/d847d34b-9337-4e2d-99a5-767e5ac9c582",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-Blob-Sec"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageQueuePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageQueuePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/bcff79fb-2b0d-47c9-97e5-3023479b00d1",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-Queue"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageQueueSecPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageQueueSecPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/da9b4ae8-5ddc-48c5-b9c0-25f8abf7a3d6",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-Queue-Sec"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageFilePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageFilePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/6df98d03-368a-4438-8730-a93c4d7693d6",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-File"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageStaticWebPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageStaticWebPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/9adab2a5-05ba-4fbd-831a-5bf958d04218",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-StaticWeb"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageStaticWebSecPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageStaticWebSecPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/d19ae5f1-b303-4b82-9ca8-7682749faf0c",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-StaticWeb-Sec"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageDFSPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageDFSPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/83c6fe0f-2316-444a-99a1-1ecd8a7872ca",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-DFS"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageDFSSecPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageDFSSecPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/90bd4cb3-9f59-45f7-a6ca-f69db2726671",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-DFS-Sec"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureSynapseSQLPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureSynapseSQLPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "targetSubResource": {
            "value": "Sql"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/1e5ed725-f16c-478b-bd4b-7bfa2f7940b9",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Synapse-SQL"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureSynapseSQLODPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureSynapseSQLODPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "targetSubResource": {
            "value": "SqlOnDemand"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/1e5ed725-f16c-478b-bd4b-7bfa2f7940b9",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Synapse-SQL-OnDemand"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureSynapseDevPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureSynapseDevPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "targetSubResource": {
            "value": "Dev"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/1e5ed725-f16c-478b-bd4b-7bfa2f7940b9",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Synapse-Dev"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "groupId": {
            "value": "keydelivery"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMediaServicesKeyPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMediaServicesKeyPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b4a7f6c1-585e-4177-ad5b-c2c93f4bb991",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-MediaServices-Key"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "groupId": {
            "value": "liveevent"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMediaServicesLivePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMediaServicesLivePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b4a7f6c1-585e-4177-ad5b-c2c93f4bb991",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-MediaServices-Live"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "groupId": {
            "value": "streamingendpoint"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMediaServicesStreamPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMediaServicesStreamPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b4a7f6c1-585e-4177-ad5b-c2c93f4bb991",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-MediaServices-Stream"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId1": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMonitorPrivateDnsZoneId1'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMonitorPrivateDnsZoneId1, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateDnsZoneId2": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMonitorPrivateDnsZoneId2'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMonitorPrivateDnsZoneId2, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateDnsZoneId3": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMonitorPrivateDnsZoneId3'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMonitorPrivateDnsZoneId3, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateDnsZoneId4": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMonitorPrivateDnsZoneId4'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMonitorPrivateDnsZoneId4, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateDnsZoneId5": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMonitorPrivateDnsZoneId5'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMonitorPrivateDnsZoneId5, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/437914ee-c176-4fff-8986-7e05eb971365",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Monitor"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureWebPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureWebPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0b026355-49cb-467b-8ac4-f777874e175a",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Web"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureBatchPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureBatchPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/4ec38ebc-381f-45ee-81a4-acbc4be878f8",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Batch"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureAppPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureAppPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/7a860e27-9ca2-4fc6-822d-c2d248c300df",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-App"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureAsrPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureAsrPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/942bd215-1a66-44be-af65-6a1c0318dbe2",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Site-Recovery"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureIotPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureIotPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/aaa64d2d-2fa3-45e5-b332-0b031b9b30e8",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-IoT"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureKeyVaultPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureKeyVaultPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/ac673a9a-f77d-4846-b2d8-a57f8e1c01d4",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-KeyVault"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureSignalRPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureSignalRPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b0e86710-7fb7-4a6c-a064-32e9b829509e",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-SignalR"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureAppServicesPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureAppServicesPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b318f84a-b872-429b-ac6d-a01b96814452",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-AppServices"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect1')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureEventGridTopicsPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureEventGridTopicsPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/baf19753-7502-405f-8745-370519b20483",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-EventGridTopics"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureDiskAccessPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureDiskAccessPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/bc05b96c-0b36-4ca9-82f0-5c53f96ce05a",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-DiskAccess"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureCognitiveServicesPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureCognitiveServicesPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/c4bc6f10-cb41-49eb-b000-d5ab82e2a091",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-CognitiveServices"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect1')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureIotHubsPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureIotHubsPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/c99ce9c1-ced7-4c3e-aca0-10e69ce0cb02",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-IoTHubs"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect1')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureEventGridDomainsPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureEventGridDomainsPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/d389df0a-e0d7-4607-833c-75a6fdac2c2d",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-EventGridDomains"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureRedisCachePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureRedisCachePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/e016b22b-e0eb-436d-8fd7-160c4eaed6e2",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-RedisCache"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureAcrPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureAcrPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/e9585a95-5b8c-4d03-b193-dc7eb5ac4c32",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-ACR"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureEventHubNamespacePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureEventHubNamespacePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/ed66d4f5-8220-45dc-ab4a-20d1749c74e6",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-EventHubNamespace"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMachineLearningWorkspacePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMachineLearningWorkspacePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "secondPrivateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureMachineLearningWorkspaceSecondPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureMachineLearningWorkspaceSecondPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/ee40564d-486e-4f68-a5ca-7a621edae0fb",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-MachineLearningWorkspace"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureServiceBusNamespacePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureServiceBusNamespacePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/f0fcf93c-c063-4071-9668-c47474bd3564",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-ServiceBusNamespace"
      },
      {
        "groupNames": [],
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureCognitiveSearchPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureCognitiveSearchPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/fbc14a67-53e4-4932-abcc-2049c6706009",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-CognitiveSearch"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureBotServicePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureBotServicePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/6a4e6f44-f2af-4082-9702-033c9e88b9f8",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-BotService"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureManagedGrafanaWorkspacePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureManagedGrafanaWorkspacePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/4c8537f8-cd1b-49ec-b704-18e82a42fd58",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-ManagedGrafanaWorkspace"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureVirtualDesktopHostpoolPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureVirtualDesktopHostpoolPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "connection"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/9427df23-0f42-4e1e-bf99-a6133d841c4a",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-VirtualDesktopHostpool"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureVirtualDesktopWorkspacePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureVirtualDesktopWorkspacePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateEndpointGroupId": {
            "value": "feed"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/34804460-d88b-4922-a7ca-537165e060ed",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-VirtualDesktopWorkspace"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureIotDeviceupdatePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureIotDeviceupdatePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/a222b93a-e6c2-4c01-817f-21e092455b2a",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-IoTDeviceupdate"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneIDForGuestConfiguration": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureArcGuestconfigurationPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureArcGuestconfigurationPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateDnsZoneIDForHybridResourceProvider": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureArcHybridResourceProviderPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureArcHybridResourceProviderPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateDnsZoneIDForKubernetesConfiguration": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureArcKubernetesConfigurationPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureArcKubernetesConfigurationPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/55c4db33-97b0-437b-8469-c4f4498f5df9",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Arc"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureIotCentralPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureIotCentralPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/d627d7c6-ded5-481a-8f2e-7e16b1e6faf6",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-IoTCentral"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageTablePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageTablePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/028bbd88-e9b5-461f-9424-a1b63a7bee1a",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-Table"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZoneId": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureStorageTableSecondaryPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureStorageTableSecondaryPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/c1d634a5-f73d-4cdd-889f-2cc7006eb47f",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Storage-Table-Secondary"
      },
      {
        "parameters": {
          "effect": {
            "value": "[parameters('effect')]"
          },
          "privateDnsZone-Backup": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureSiteRecoveryBackupPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureSiteRecoveryBackupPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateDnsZone-Blob": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureSiteRecoveryBlobPrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureSiteRecoveryBlobPrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          },
          "privateDnsZone-Queue": {
            "value": "[if(equals(parameters('dnsZoneSubscriptionId'), ''), parameters('azureSiteRecoveryQueuePrivateDnsZoneId'), format('/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}', parameters('dnsZoneSubscriptionId'), toLower(parameters('dnsZoneResourceGroupName')), parameters('dnsZoneResourceType'), replace(replace(parameters('dnsZoneNames').azureSiteRecoveryQueuePrivateDnsZoneId, '{regionName}', parameters('dnsZoneRegion')), '{regionCode}', parameters('dnzZoneRegionShortNames')[parameters('dnsZoneRegion')])))]"
          }
        },
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/af783da1-4ad1-42be-800d-d19c70038820",
        "policyDefinitionReferenceId": "DINE-Private-DNS-Azure-Site-Recovery-Backup"
      }
    ],
    "policyType": "Custom"
  },
  "type": "Microsoft.Authorization/policySetDefinitions"
}`
	result := new(armpolicy.SetDefinition)
	_ = result.UnmarshalJSON([]byte(source))
	return result
}

func deployPrivateDnsZonesPolicyAssignment() *armpolicy.Assignment {
	source := `{
  "type": "Microsoft.Authorization/policyAssignments",
  "apiVersion": "2022-06-01",
  "name": "Deploy-Private-DNS-Zones",
  "location": "${default_location}",
  "dependsOn": [],
  "identity": {
    "type": "SystemAssigned"
  },
  "properties": {
    "description": "This policy initiative is a group of policies that ensures private endpoints to Azure PaaS services are integrated with Azure Private DNS zones",
    "displayName": "Configure Azure PaaS services to use private DNS zones",
    "policyDefinitionId": "/providers/Microsoft.Management/managementGroups/placeholder/providers/Microsoft.Authorization/policySetDefinitions/Deploy-Private-DNS-Zones",
    "enforcementMode": "Default",
    "nonComplianceMessages": [
      {
        "message": "Azure PaaS services {enforcementMode} use private DNS zones."
      }
    ],
    "parameters": {
      "azureFilePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.afs.azure.net"
      },
      "azureAutomationWebhookPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azure-automation.net"
      },
      "azureAutomationDSCHybridPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azure-automation.net"
      },
      "azureCosmosSQLPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.documents.azure.com"
      },
      "azureCosmosMongoPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.mongo.cosmos.azure.com"
      },
      "azureCosmosCassandraPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.cassandra.cosmos.azure.com"
      },
      "azureCosmosGremlinPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.gremlin.cosmos.azure.com"
      },
      "azureCosmosTablePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.table.cosmos.azure.com"
      },
      "azureDataFactoryPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.datafactory.azure.net"
      },
      "azureDataFactoryPortalPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.adf.azure.com"
      },
      "azureDatabricksPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azuredatabricks.net"
      },
      "azureHDInsightPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azurehdinsight.net"
      },
      "azureMigratePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.prod.migration.windowsazure.com"
      },
      "azureStorageBlobPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
      },
      "azureStorageBlobSecPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
      },
      "azureStorageQueuePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.queue.core.windows.net"
      },
      "azureStorageQueueSecPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.queue.core.windows.net"
      },
      "azureStorageFilePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.file.core.windows.net"
      },
      "azureStorageStaticWebPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.web.core.windows.net"
      },
      "azureStorageStaticWebSecPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.web.core.windows.net"
      },
      "azureStorageDFSPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.dfs.core.windows.net"
      },
      "azureStorageDFSSecPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.dfs.core.windows.net"
      },
      "azureSynapseSQLPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.sql.azuresynapse.net"
      },
      "azureSynapseSQLODPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.sql.azuresynapse.net"
      },
      "azureSynapseDevPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.dev.azuresynapse.net"
      },
      "azureMediaServicesKeyPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.media.azure.net"
      },
      "azureMediaServicesLivePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.media.azure.net"
      },
      "azureMediaServicesStreamPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.media.azure.net"
      },
      "azureMonitorPrivateDnsZoneId1": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.monitor.azure.com"
      },
      "azureMonitorPrivateDnsZoneId2": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.oms.opinsights.azure.com"
      },
      "azureMonitorPrivateDnsZoneId3": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.ods.opinsights.azure.com"
      },
      "azureMonitorPrivateDnsZoneId4": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.agentsvc.azure-automation.net"
      },
      "azureMonitorPrivateDnsZoneId5": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
      },
      "azureWebPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.webpubsub.azure.com"
      },
      "azureBatchPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.batch.azure.com"
      },
      "azureAppPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azconfig.io"
      },
      "azureAsrPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.siterecovery.windowsazure.com"
      },
      "azureIotPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azure-devices-provisioning.net"
      },
      "azureKeyVaultPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
      },
      "azureSignalRPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.service.signalr.net"
      },
      "azureAppServicesPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azurewebsites.net"
      },
      "azureEventGridTopicsPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.eventgrid.azure.net"
      },
      "azureDiskAccessPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
      },
      "azureCognitiveServicesPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.cognitiveservices.azure.com"
      },
      "azureIotHubsPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azure-devices.net"
      },
      "azureEventGridDomainsPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.eventgrid.azure.net"
      },
      "azureRedisCachePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.redis.cache.windows.net"
      },
      "azureAcrPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azurecr.io"
      },
      "azureEventHubNamespacePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.servicebus.windows.net"
      },
      "azureMachineLearningWorkspacePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.api.azureml.ms"
      },
      "azureMachineLearningWorkspaceSecondPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.notebooks.azure.net"
      },
      "azureServiceBusNamespacePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.servicebus.windows.net"
      },
      "azureCognitiveSearchPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.search.windows.net"
      },
      "azureBotServicePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.directline.botframework.com"
      },
      "azureManagedGrafanaWorkspacePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.grafana.azure.com"
      },
      "azureVirtualDesktopHostpoolPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.wvd.microsoft.com"
      },
      "azureVirtualDesktopWorkspacePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.wvd.microsoft.com"
      },
      "azureIotDeviceupdatePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azure-devices.net"
      },
      "azureArcGuestconfigurationPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.guestconfiguration.azure.com"
      },
      "azureArcHybridResourceProviderPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.his.arc.azure.com"
      },
      "azureArcKubernetesConfigurationPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.dp.kubernetesconfiguration.azure.com"
      },
      "azureIotCentralPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.azureiotcentral.com"
      },
      "azureStorageTablePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.table.core.windows.net"
      },
      "azureStorageTableSecondaryPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.table.core.windows.net"
      },
      "azureSiteRecoveryBackupPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.ne.backup.windowsazure.com"
      },
      "azureSiteRecoveryBlobPrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
      },
      "azureSiteRecoveryQueuePrivateDnsZoneId": {
        "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/placeholder/providers/Microsoft.Network/privateDnsZones//providers/Microsoft.Network/privateDnsZones/privatelink.queue.core.windows.net"
      }
    },
    "scope": "/providers/Microsoft.Management/managementGroups/placeholder",
    "notScopes": []
  }
}`
	result := new(armpolicy.Assignment)
	_ = result.UnmarshalJSON([]byte(source))
	return result
}
