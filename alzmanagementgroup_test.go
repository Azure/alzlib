package alzlib

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/matt-FFFFFF/alzlib/to"
	"github.com/stretchr/testify/assert"
)

func TestE2E(t *testing.T) {
	az := NewAlzLib()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	assert.NoError(t, err)
	az.AddPolicyClient(cf)
	assert.NoError(t, az.Init(ctx, Lib))
	vals := &WellKnownPolicyValues{
		DefaultLocation:                "eastus",
		DefaultLogAnalyticsWorkspaceId: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.OperationalInsights/workspaces/testlaworkspaceid",
	}
	arch, err := az.CopyArchetype("root", vals)
	assert.NoError(t, err)
	assert.NoError(t, az.AddManagementGroupToDeployment("root", "root", "external", true, arch))
	err = az.Deployment.mgs["root"].GeneratePolicyAssignmentAdditionalRoleAssignments(az)
	assert.NoError(t, err)
}

func TestGeneratePolicyAssignmentAdditionalRoleAssignments(t *testing.T) {
	t.Parallel()
	// create a new AlzLib instance.
	az := NewAlzLib()

	// create a new AlzManagementGroup instance.
	alzmg := &AlzManagementGroup{
		additionalRoleAssignmentsByPolicyAssignment: make(map[string]*PolicyAssignmentAdditionalRoleAssignments),
		policyDefinitions:    make(map[string]*armpolicy.Definition),
		policySetDefinitions: make(map[string]*armpolicy.SetDefinition),
		policyAssignments:    make(map[string]*armpolicy.Assignment),
		mu:                   sync.RWMutex{},
	}

	// create a new policy assignment for the definition.
	paDef := &armpolicy.Assignment{
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
	}

	// create a new policy assignment for the definition.
	paSetDef := &armpolicy.Assignment{
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
	}

	ps := &armpolicy.SetDefinition{
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
	}

	// create a new policy definition for direct assignment.
	pd1 := &armpolicy.Definition{
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
	}

	// create a new policy definition for set assignment.
	pd2 := &armpolicy.Definition{
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
	}

	// add the policy (set) definitions to the arch.
	alzmg.policyDefinitions[*pd1.Name] = pd1
	alzmg.policyDefinitions[*pd2.Name] = pd2
	alzmg.policySetDefinitions[*ps.Name] = ps

	// add the policy assignments to the arch.
	alzmg.policyAssignments[*paDef.Name] = paDef
	alzmg.policyAssignments[*paSetDef.Name] = paSetDef

	// add the policy (set) definitions to the alzlib.
	az.policyDefinitions[*pd2.Name] = pd2
	az.policyDefinitions[*pd1.Name] = pd1
	az.policySetDefinitions[*ps.Name] = ps
	// add the policy assignments to the arch.
	az.policyAssignments[*paDef.Name] = paDef
	az.policyAssignments[*paSetDef.Name] = paSetDef

	// generate the additional role assignments.
	err := alzmg.GeneratePolicyAssignmentAdditionalRoleAssignments(az)

	// check that there were no errors.
	assert.NoError(t, err)

	// check that the additional role assignments were generated correctly.
	additionalRas, ok := alzmg.additionalRoleAssignmentsByPolicyAssignment[*paDef.Name]
	assert.True(t, ok)
	assert.Equal(t, []string{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition"}, additionalRas.RoleDefinitionIds.ToSlice())
	assert.Equal(t, []string{paDef.Properties.Parameters["parameter1"].Value.(string)}, additionalRas.AdditionalScopes.ToSlice()) //nolint:forcetypeassert
	additionalSetRas, ok := alzmg.additionalRoleAssignmentsByPolicyAssignment[*paSetDef.Name]
	assert.True(t, ok)
	assert.Equal(t, []string{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition2"}, additionalSetRas.RoleDefinitionIds.ToSlice())
	assert.Equal(t, []string{paSetDef.Properties.Parameters["setparameter1"].Value.(string)}, additionalSetRas.AdditionalScopes.ToSlice()) //nolint:forcetypeassert
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
	alzmg := &AlzManagementGroup{
		name: "mg1",
		policyAssignments: map[string]*armpolicy.Assignment{
			"pa1": {
				Name: to.Ptr("pa1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd1")),
					Scope:              to.Ptr(fmt.Sprintf(managementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			},
		},
		wkpv: &WellKnownPolicyValues{
			DefaultLocation: "eastus",
		},
		mu: sync.RWMutex{},
	}
	pd2mg := map[string]string{
		"pd1": "mg1",
	}
	psd2mg := map[string]string{}
	wkpv := &WellKnownPolicyValues{
		DefaultLocation: "eastus",
	}
	papv := getWellKnownPolicyAssignmentParameterValues(wkpv)
	err := modifyPolicyAssignments(alzmg, pd2mg, psd2mg, papv)
	assert.NoError(t, err)
	expected := fmt.Sprintf(policyAssignmentIdFmt, "mg1", "pa1")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa1"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa1"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *alzmg.policyAssignments["pa1"].Location)

	// Test with multiple policy assignments and policy definitions.
	alzmg = &AlzManagementGroup{
		name: "mg1",
		policyAssignments: map[string]*armpolicy.Assignment{
			"pa1": {
				Name: to.Ptr("pa1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd1")),
					Scope:              to.Ptr(fmt.Sprintf(managementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			},
			"pa2": {
				Name: to.Ptr("pa2"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(policySetDefinitionIdFmt, "changeme", "psd1")),
					Scope:              to.Ptr(fmt.Sprintf(managementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			},
		},
		wkpv: &WellKnownPolicyValues{
			DefaultLocation: "eastus",
		},
		mu: sync.RWMutex{},
	}
	pd2mg = map[string]string{
		"pd1": "mg1",
	}
	psd2mg = map[string]string{
		"psd1": "mg1",
	}
	err = modifyPolicyAssignments(alzmg, pd2mg, psd2mg, papv)
	assert.NoError(t, err)
	expected = fmt.Sprintf(policyAssignmentIdFmt, "mg1", "pa1")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa1"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa1"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *alzmg.policyAssignments["pa1"].Location)
	expected = fmt.Sprintf(policyAssignmentIdFmt, "mg1", "pa2")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa2"].ID)
	expected = fmt.Sprintf(policySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa2"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.policyAssignments["pa2"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *alzmg.policyAssignments["pa2"].Location)

	// Test with invalid policy definition id.
	alzmg = &AlzManagementGroup{
		name: "mg1",
		policyAssignments: map[string]*armpolicy.Assignment{
			"pa1": {
				Name: to.Ptr("policy1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr("invalid"),
					Scope:              to.Ptr(fmt.Sprintf(managementGroupIdFmt, "mg1")),
				},
			},
		},
		wkpv: &WellKnownPolicyValues{
			DefaultLocation: "eastus",
		},
		mu: sync.RWMutex{},
	}
	pd2mg = map[string]string{}
	psd2mg = map[string]string{}
	err = modifyPolicyAssignments(alzmg, pd2mg, psd2mg, papv)
	assert.Error(t, err)
	expected = "has invalid resource type in id"
	assert.ErrorContains(t, err, expected)
}

func TestModifyPolicyDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single policy definition.
	alzmg := &AlzManagementGroup{
		name: "mg1",
		policyDefinitions: map[string]*armpolicy.Definition{
			"pd1": {},
		},
	}
	modifyPolicyDefinitions(alzmg)
	expected := fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policyDefinitions["pd1"].ID)

	// Test with multiple policy definitions.
	alzmg = &AlzManagementGroup{
		name: "mg1",
		policyDefinitions: map[string]*armpolicy.Definition{
			"pd1": {},
			"pd2": {},
		},
	}
	modifyPolicyDefinitions(alzmg)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policyDefinitions["pd1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd2")
	assert.Equal(t, expected, *alzmg.policyDefinitions["pd2"].ID)

	// Test with no policy definitions.
	alzmg = &AlzManagementGroup{
		name:              "mg1",
		policyDefinitions: map[string]*armpolicy.Definition{},
	}
	modifyPolicyDefinitions(alzmg)
	assert.Empty(t, alzmg.policyDefinitions)
}

func TestModifyPolicySetDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single policy set definition and a single policy definition.
	alzmg := &AlzManagementGroup{
		name: "mg1",
		policySetDefinitions: map[string]*armpolicy.SetDefinition{
			"psd1": {
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd1")),
						},
					},
				},
			},
		},
	}
	pd2mg := map[string]string{
		"pd1": "mg1",
	}
	modifyPolicySetDefinitions(alzmg, pd2mg)
	expected := fmt.Sprintf(policySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd1"].Properties.PolicyDefinitions[0].PolicyDefinitionID)

	// Test with multiple policy set definitions and policy definitions.
	alzmg = &AlzManagementGroup{
		name: "mg1",
		policySetDefinitions: map[string]*armpolicy.SetDefinition{
			"psd1": {
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd1")),
						},
					},
				},
			},
			"psd2": {
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd2")),
						},
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd3")),
						},
					},
				},
			},
		},
	}
	pd2mg = map[string]string{
		"pd1": "mg1",
		"pd2": "mg1",
		"pd3": "mg1",
	}
	modifyPolicySetDefinitions(alzmg, pd2mg)
	expected = fmt.Sprintf(policySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd1"].Properties.PolicyDefinitions[0].PolicyDefinitionID)
	expected = fmt.Sprintf(policySetDefinitionIdFmt, "mg1", "psd2")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd2"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd2")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd2"].Properties.PolicyDefinitions[0].PolicyDefinitionID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd3")
	assert.Equal(t, expected, *alzmg.policySetDefinitions["psd2"].Properties.PolicyDefinitions[1].PolicyDefinitionID)

	// Test with no policy set definitions or policy definitions.
	alzmg = &AlzManagementGroup{
		name:                 "mg1",
		policySetDefinitions: map[string]*armpolicy.SetDefinition{},
	}
	pd2mg = map[string]string{}
	modifyPolicySetDefinitions(alzmg, pd2mg)
	assert.Empty(t, alzmg.policySetDefinitions)
}

func TestModifyRoleDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single role definition
	alzmg := &AlzManagementGroup{
		name: "mg1",
		roleDefinitions: map[string]*armauthorization.RoleDefinition{
			"rd1": {
				Name: to.Ptr("role1"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
				},
			},
		},
	}
	modifyRoleDefinitions(alzmg)
	expected := fmt.Sprintf(roleDefinitionIdFmt, "mg1", uuidV5("mg1", "role1"))
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd1"].ID)
	assert.Len(t, alzmg.roleDefinitions["rd1"].Properties.AssignableScopes, 1)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd1"].Properties.AssignableScopes[0])

	// Test with multiple role definitions
	alzmg = &AlzManagementGroup{
		name: "mg1",
		roleDefinitions: map[string]*armauthorization.RoleDefinition{
			"rd1": {
				Name: to.Ptr("role1"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
				},
			},
			"rd2": {
				Name: to.Ptr("role2"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
				},
			},
		},
	}
	modifyRoleDefinitions(alzmg)
	expected = fmt.Sprintf(roleDefinitionIdFmt, "mg1", uuidV5("mg1", "role1"))
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd1"].ID)
	assert.Len(t, alzmg.roleDefinitions["rd1"].Properties.AssignableScopes, 1)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd1"].Properties.AssignableScopes[0])
	assert.Equal(t, fmt.Sprintf(managementGroupIdFmt, "mg1"), *alzmg.roleDefinitions["rd1"].Properties.AssignableScopes[0])
	expected = fmt.Sprintf(roleDefinitionIdFmt, "mg1", uuidV5("mg1", "role2"))
	assert.Equal(t, expected, *alzmg.roleDefinitions["rd2"].ID)
	assert.Len(t, alzmg.roleDefinitions["rd2"].Properties.AssignableScopes, 1)
	assert.Equal(t, fmt.Sprintf(managementGroupIdFmt, "mg1"), *alzmg.roleDefinitions["rd2"].Properties.AssignableScopes[0])

	// Test with no role definitions.
	alzmg = &AlzManagementGroup{
		name:            "mg1",
		roleDefinitions: map[string]*armauthorization.RoleDefinition{},
	}
	modifyRoleDefinitions(alzmg)
	assert.Empty(t, alzmg.roleDefinitions)
}

func TestUpsertPolicyAssignments(t *testing.T) {
	// Create a new AlzLib instance.
	az := NewAlzLib()
	az.policyDefinitions = map[string]*armpolicy.Definition{
		"test-policy-definition": {},
	}

	// Create a new AlzManagementGroup instance.
	alzmg := &AlzManagementGroup{
		policyAssignments: make(map[string]*armpolicy.Assignment),
		mu:                sync.RWMutex{},
	}

	// Create a new policy assignment to upsert.
	pa := &armpolicy.Assignment{
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
	}

	// Upsert the policy assignment.
	err := alzmg.UpsertPolicyAssignments(context.Background(), map[string]*armpolicy.Assignment{"test-policy-assignment": pa}, az)
	assert.NoError(t, err)

	// Verify that the policy assignment was added to the management group.
	assert.Equal(t, 1, len(alzmg.policyAssignments))
	assert.Equal(t, pa, alzmg.policyAssignments["test-policy-assignment"])

	// Update the policy assignment.
	pa.Properties.Parameters["parameter1"].Value = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/my-rg"
	pa.Properties.Parameters["parameter2"].Value = "value3"

	// Upsert the updated policy assignment.
	err = alzmg.UpsertPolicyAssignments(context.Background(), map[string]*armpolicy.Assignment{"test-policy-assignment": pa}, az)
	assert.NoError(t, err)

	// Verify that the policy assignment was updated in the management group.
	assert.Equal(t, 1, len(alzmg.policyAssignments))
	assert.Equal(t, pa, alzmg.policyAssignments["test-policy-assignment"])

	// Add a new policy assignment.
	pa2 := &armpolicy.Assignment{
		Name: to.Ptr("test-policy-assignment-2"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),

		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition-2"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"parameter1": {Value: "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/my-rg"},
				"parameter2": {Value: "value4"},
			},
		},
	}

	// Upsert the new policy assignment.
	err = alzmg.UpsertPolicyAssignments(context.Background(), map[string]*armpolicy.Assignment{"test-policy-assignment-2": pa2}, az)
	assert.NoError(t, err)

	// Verify that the new policy assignment was added to the management group.
	assert.Equal(t, 2, len(alzmg.policyAssignments))
	assert.Equal(t, pa, alzmg.policyAssignments["test-policy-assignment"])
	assert.Equal(t, pa2, alzmg.policyAssignments["test-policy-assignment-2"])
}

func TestCopyMap(t *testing.T) {
	// Create a new map.
	m := map[string]*int{
		"foo": to.Ptr(1),
		"bar": to.Ptr(2),
		"baz": to.Ptr(3),
	}

	// Copy the map.
	m2 := copyMap[string, int](m)

	// Verify that the original map and the copied map are equal.
	assert.Equal(t, len(m), len(m2))
	for k, v := range m {
		assert.Equal(t, *v, m2[k])
	}

	// Modify the original map.
	m["foo"] = to.Ptr(4)

	// Verify that the original map and the copied map are no longer equal.
	assert.NotEqual(t, m, m2)
}
