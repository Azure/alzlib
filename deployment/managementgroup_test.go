package deployment

import (
	"context"
	"fmt"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddManagementGroup(t *testing.T) {
	t.Parallel()
	// create a new deployment type.
	wkvs := &WellKnownPolicyValues{
		DefaultLocation: to.Ptr("eastus"),
	}
	az := NewAlzLib()

	// create a new archetype
	arch := &Archetype{
		PolicyDefinitions:    mapset.NewSet[string](),
		PolicySetDefinitions: mapset.NewSet[string](),
		PolicyAssignments:    mapset.NewSet[string](),
		RoleDefinitions:      mapset.NewSet[string](),
	}
	arch.wellKnownPolicyValues = wkvs

	// test adding a new management group with no parent.
	req := AlzManagementGroupAddRequest{
		Id:               "mg1",
		DisplayName:      "mg1",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	err := az.AddManagementGroupToDeployment(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, az.Deployment.mgs, 1)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Equal(t, "mg1", az.Deployment.mgs["mg1"].name)
	assert.Equal(t, "mg1", az.Deployment.mgs["mg1"].displayName)
	assert.Nil(t, az.Deployment.mgs["mg1"].parent)
	assert.Equal(t, az.Deployment.mgs["mg1"].children.Cardinality(), 0)
	assert.True(t, az.Deployment.mgs["mg1"].ParentIsExternal())
	assert.Equal(t, fmt.Sprintf(managementGroupIdFmt, "mg1"), az.Deployment.mgs["mg1"].GetResourceId())

	req = AlzManagementGroupAddRequest{
		Id:               "mg2",
		DisplayName:      "mg2",
		ParentId:         "mg1",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	// test adding a new management group with a parent.
	err = az.AddManagementGroupToDeployment(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg2")
	assert.Equal(t, "mg2", az.Deployment.mgs["mg2"].name)
	assert.Equal(t, "mg2", az.Deployment.mgs["mg2"].displayName)
	assert.NotNil(t, az.Deployment.mgs["mg2"].parent)
	assert.Equal(t, "mg1", az.Deployment.mgs["mg2"].parent.name)
	assert.Equal(t, az.Deployment.mgs["mg1"].children.Cardinality(), 1)
	assert.Equal(t, "mg2", az.Deployment.mgs["mg1"].children.ToSlice()[0].name)
	assert.False(t, az.Deployment.mgs["mg2"].ParentIsExternal())
	assert.Equal(t, az.Deployment.mgs["mg1"], az.Deployment.mgs["mg2"].GetParentMg())

	req = AlzManagementGroupAddRequest{
		Id:               "mg3",
		DisplayName:      "mg3",
		ParentId:         "mg4",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	// test adding a new management group with a non-existent parent.
	err = az.AddManagementGroupToDeployment(context.Background(), req)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
	assert.NotContains(t, az.Deployment.mgs, "mg3")

	req = AlzManagementGroupAddRequest{
		Id:               "mg4",
		DisplayName:      "mg4",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	// test adding a new management group with multiple root management groups.
	err = az.AddManagementGroupToDeployment(context.Background(), req)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
	assert.NotContains(t, az.Deployment.mgs, "mg4")

	req = AlzManagementGroupAddRequest{
		Id:               "mg1",
		DisplayName:      "mg1",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	// test adding a new management group with an existing name.
	err = az.AddManagementGroupToDeployment(context.Background(), req)
	assert.Error(t, err)
	assert.Len(t, az.Deployment.mgs, 2)
	assert.Contains(t, az.Deployment.mgs, "mg1")
	assert.Contains(t, az.Deployment.mgs, "mg2")
}


func TestGeneratePolicyAssignmentAdditionalRoleAssignments(t *testing.T) {
	t.Parallel()
	// create a new AlzLib instance.
	az := NewAlzLib()

	// create a new AlzManagementGroup instance.
	alzmg := &AlzManagementGroup{
		policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
		policyDefinitions:     make(map[string]*armpolicy.Definition),
		policySetDefinitions:  make(map[string]*armpolicy.SetDefinition),
		policyAssignments:     make(map[string]*armpolicy.Assignment),
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
	//additionalRas, ok := alzmg.policyRoleAssignments[*paDef.Name]
	assert.Equal(t, alzmg.policyRoleAssignments.Cardinality(), 4)

	assert.True(t, alzmg.policyRoleAssignments.Contains(PolicyRoleAssignment{
		AssignmentName:   *paDef.Name,
		RoleDefinitionId: pd1.Properties.PolicyRule.(map[string]any)["then"].(map[string]any)["details"].(map[string]any)["roleDefinitionIds"].([]any)[0].(string), //nolint:forcetypeassert
		Scope:            alzmg.GetResourceId(),
	}))
	assert.True(t, alzmg.policyRoleAssignments.Contains(PolicyRoleAssignment{
		AssignmentName:   *paDef.Name,
		RoleDefinitionId: pd1.Properties.PolicyRule.(map[string]any)["then"].(map[string]any)["details"].(map[string]any)["roleDefinitionIds"].([]any)[0].(string), //nolint:forcetypeassert
		Scope:            paDef.Properties.Parameters["parameter1"].Value.(string),                                                                                 //nolint:forcetypeassert
	}))
	assert.True(t, alzmg.policyRoleAssignments.Contains(PolicyRoleAssignment{
		AssignmentName:   *paSetDef.Name,
		RoleDefinitionId: pd2.Properties.PolicyRule.(map[string]any)["then"].(map[string]any)["details"].(map[string]any)["roleDefinitionIds"].([]any)[0].(string), //nolint:forcetypeassert
		Scope:            alzmg.GetResourceId(),
	}))
	assert.True(t, alzmg.policyRoleAssignments.Contains(PolicyRoleAssignment{
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
			DefaultLocation: to.Ptr("eastus"),
		},
	}
	pd2mg := map[string]string{
		"pd1": "mg1",
	}
	psd2mg := map[string]string{}
	wkpv := &WellKnownPolicyValues{
		DefaultLocation: to.Ptr("eastus"),
	}
	papv := getWellKnownPolicyAssignmentParameterValues(wkpv)
	err := updatePolicyAsignments(alzmg, pd2mg, psd2mg, papv)
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
			DefaultLocation: to.Ptr("eastus"),
		},
	}
	pd2mg = map[string]string{
		"pd1": "mg1",
	}
	psd2mg = map[string]string{
		"psd1": "mg1",
	}
	err = updatePolicyAsignments(alzmg, pd2mg, psd2mg, papv)
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
			DefaultLocation: to.Ptr("eastus"),
		},
	}
	pd2mg = map[string]string{}
	psd2mg = map[string]string{}
	err = updatePolicyAsignments(alzmg, pd2mg, psd2mg, papv)
	assert.Error(t, err)
	expected = "has invalid referenced definition/set resource type with id"
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
	updatePolicyDefinitions(alzmg)
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
	updatePolicyDefinitions(alzmg)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.policyDefinitions["pd1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd2")
	assert.Equal(t, expected, *alzmg.policyDefinitions["pd2"].ID)

	// Test with no policy definitions.
	alzmg = &AlzManagementGroup{
		name:              "mg1",
		policyDefinitions: map[string]*armpolicy.Definition{},
	}
	updatePolicyDefinitions(alzmg)
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
	updatePolicySetDefinitions(alzmg, pd2mg)
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
	updatePolicySetDefinitions(alzmg, pd2mg)
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
	updatePolicySetDefinitions(alzmg, pd2mg)
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
	updateRoleDefinitions(alzmg)
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
	updateRoleDefinitions(alzmg)
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
	updateRoleDefinitions(alzmg)
	assert.Empty(t, alzmg.roleDefinitions)
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

func TestModifyPolicyAssignment(t *testing.T) {
	// Create a new AlzManagementGroup instance
	alzmg := &AlzManagementGroup{
		policyAssignments: make(map[string]*armpolicy.Assignment),
	}

	// Add a policy assignment to the management group
	pa := &armpolicy.Assignment{
		Name: to.Ptr("test-policy-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),
		Properties: &armpolicy.AssignmentProperties{
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"parameter1": {Value: "value1"},
			},
		},
	}
	alzmg.policyAssignments["test-policy-assignment"] = pa

	// Define the expected modified policy assignment
	expected := &armpolicy.Assignment{
		Name: to.Ptr("test-policy-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),
		Properties: &armpolicy.AssignmentProperties{
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
	}

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
