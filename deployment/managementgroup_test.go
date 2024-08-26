// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"fmt"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
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
				"parameter2": {Value: "value2"},
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
				"setparameter2": {Value: "value2"},
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
					PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition2"),
					Parameters: map[string]*armpolicy.ParameterValuesValue{
						"parameter1": {Value: "[parameters('setparameter1')]"},
						"parameter2": {Value: "[parameters('setparameter1')]"},
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
	//additionalRas, ok := alzmg.policyRoleAssignments[*paDef.Name]
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

func TestExtractParameterNameFromArmFunction(t *testing.T) {
	t.Parallel()
	// Test with a valid parameter reference.
	value := "[parameters('parameterName')]"
	expected := "parameterName"
	actual, err := extractParameterNameFromArmFunction(value)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)

	// Test with an invalid prefix.
	value = "[param('parameterName')]"
	_, err = extractParameterNameFromArmFunction(value)
	assert.Error(t, err)

	// Test with an invalid suffix.
	value = "[parameters('parameterName')"
	_, err = extractParameterNameFromArmFunction(value)
	assert.Error(t, err)

	// Test with an invalid format.
	value = "parameters('parameterName')"
	_, err = extractParameterNameFromArmFunction(value)
	assert.Error(t, err)
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
	pd2mg := map[string]string{
		"pd1": "mg1",
	}
	psd2mg := map[string]string{}

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
	pd2mg = map[string]string{
		"pd1": "mg1",
	}
	psd2mg = map[string]string{
		"psd1": "mg1",
	}
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
	pd2mg = map[string]string{}
	psd2mg = map[string]string{}
	err = updatePolicyAsignments(mg, pd2mg, psd2mg)
	assert.Error(t, err)
	expected = "resource id 'invalid' must start with '/'"
	assert.ErrorContains(t, err, expected)
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
	pd2mg := map[string]string{
		"pd1": "mg1",
	}
	err := updatePolicySetDefinitions(alzmg, pd2mg)
	assert.NoError(t, err)
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
	pd2mg = map[string]string{
		"pd1": "mg1",
		"pd2": "mg1",
		"pd3": "mg1",
	}
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
	pd2mg = map[string]string{}
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
				},
			}),
		},
	}
	updateRoleDefinitions(alzmg)
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
				},
			}),
			"rd2": assets.NewRoleDefinition(armauthorization.RoleDefinition{
				Name: to.Ptr("role2"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
				},
			}),
		},
	}
	updateRoleDefinitions(alzmg)
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
	updateRoleDefinitions(alzmg)
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
