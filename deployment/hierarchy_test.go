// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"context"
	"reflect"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicySetDefinitionToMg(t *testing.T) {
	t.Parallel()
	// Test with a single management group and policy set definition.
	d := Hierarchy{
		mgs: map[string]*HierarchyManagementGroup{
			"mg1": {
				policySetDefinitions: map[string]*assets.PolicySetDefinition{
					"psd1": {},
				},
			},
		},
	}
	expected := make(map[string]mapset.Set[string])
	expected["psd1"] = mapset.NewThreadUnsafeSet("mg1")
	assert.Equal(t, expected, d.policySetDefinitionToMg())

	// Test with multiple management groups and policy set definitions.
	d = Hierarchy{
		mgs: map[string]*HierarchyManagementGroup{
			"mg1": {
				policySetDefinitions: map[string]*assets.PolicySetDefinition{
					"psd1": {},
				},
			},
			"mg2": {
				policySetDefinitions: map[string]*assets.PolicySetDefinition{
					"psd2": {},
					"psd3": {},
				},
			},
		},
	}
	expected["psd1"] = mapset.NewThreadUnsafeSet("mg1")
	expected["psd2"] = mapset.NewThreadUnsafeSet("mg2")
	expected["psd3"] = mapset.NewThreadUnsafeSet("mg2")

	assert.Equal(t, expected, d.policySetDefinitionToMg())

	// Test with no management groups or policy set definitions.
	d = Hierarchy{}
	expected = make(map[string]mapset.Set[string])
	assert.Equal(t, expected, d.policySetDefinitionToMg())
}

func TestPolicyDefinitionToMg(t *testing.T) {
	t.Parallel()
	// Test with a single management group and policy definition.
	d := Hierarchy{
		mgs: map[string]*HierarchyManagementGroup{
			"mg1": {
				policyDefinitions: map[string]*assets.PolicyDefinition{
					"pd1": {},
				},
			},
		},
	}
	expected := make(map[string]mapset.Set[string])
	expected["pd1"] = mapset.NewThreadUnsafeSet("mg1")
	assert.Equal(t, expected, d.policyDefinitionToMg())

	// Test with multiple management groups and policy definitions.
	d = Hierarchy{
		mgs: map[string]*HierarchyManagementGroup{
			"mg1": {
				policyDefinitions: map[string]*assets.PolicyDefinition{
					"pd1": {},
				},
			},
			"mg2": {
				policyDefinitions: map[string]*assets.PolicyDefinition{
					"pd2": {},
					"pd3": {},
				},
			},
		},
	}
	expected["pd1"] = mapset.NewThreadUnsafeSet("mg1")
	expected["pd2"] = mapset.NewThreadUnsafeSet("mg2")
	expected["pd3"] = mapset.NewThreadUnsafeSet("mg2")
	assert.Equal(t, expected, d.policyDefinitionToMg())

	// Test with no management groups or policy definitions.
	d = Hierarchy{}
	expected = make(map[string]mapset.Set[string])
	assert.Equal(t, expected, d.policyDefinitionToMg())
}

func TestNewUUID(t *testing.T) {
	t.Parallel()
	// create a new UUID namespace.
	ns := uuid.MustParse("d97506b3-4470-5694-a203-2c37e477d3ac")

	u := uuidV5("foo", "bar", "baz")

	assert.Equal(t, ns.String(), u.String())
}

func TestPolicyRoleAssignments(t *testing.T) {
	t.Parallel()

	t.Run("returns valid role assignments even when PolicyRoleAssignmentErrors occurs", func(t *testing.T) {
		t.Parallel()

		az := alzlib.NewAlzLib(nil)

		// Create a policy definition with roleDefinitionIds (this triggers role assignment generation).
		// Use proper structure with Parameters map to avoid errors.
		pd1 := assets.NewPolicyDefinition(armpolicy.Definition{
			Name: to.Ptr("test-policy-definition"),
			Properties: &armpolicy.DefinitionProperties{
				PolicyRule: map[string]any{
					"then": map[string]any{
						"details": map[string]any{
							"roleDefinitionIds": []any{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition"},
						},
					},
				},
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{},
			},
		})

		// Create a policy definition for the policy set.
		pd2 := assets.NewPolicyDefinition(armpolicy.Definition{
			Name: to.Ptr("test-policy-definition2"),
			Properties: &armpolicy.DefinitionProperties{
				PolicyRule: map[string]any{
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
				},
			},
		})

		// Create a policy set that references pd2 with an ARM function that will fail to parse
		// (we supply an invalid ARM expression).
		ps := assets.NewPolicySetDefinition(armpolicy.SetDefinition{
			Name: to.Ptr("test-policy-set-definition"),
			Properties: &armpolicy.SetDefinitionProperties{
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
					"setparameter1": {
						Type: to.Ptr(armpolicy.ParameterTypeString),
					},
				},
				PolicyDefinitions: []*armpolicy.DefinitionReference{
					{
						PolicyDefinitionReferenceID: to.Ptr("test-policy-definition2-ref"),
						PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition2"),
						Parameters: map[string]*armpolicy.ParameterValuesValue{
							// Invalid ARM expression to trigger PolicyRoleAssignmentErrors.
							"parameter1": {Value: "[invalid('arm','expression'"},
						},
					},
				},
			},
		})

		// Add definitions to AlzLib.
		_ = az.AddPolicyDefinitions(pd1, pd2)
		_ = az.AddPolicySetDefinitions(ps)

		// Create a valid policy assignment for mg1 (uses pd1, will succeed).
		pa1 := assets.NewPolicyAssignment(armpolicy.Assignment{
			Name:     to.Ptr("test-policy-assignment1"),
			Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
			Properties: &armpolicy.AssignmentProperties{
				PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition"),
			},
		})

		// Create a policy assignment for mg2 that will cause PolicyRoleAssignmentErrors
		// (uses policy set with invalid ARM expression).
		pa2 := assets.NewPolicyAssignment(armpolicy.Assignment{
			Name:     to.Ptr("test-policy-assignment2"),
			Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
			Properties: &armpolicy.AssignmentProperties{
				PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/test-policy-set-definition"),
				Parameters: map[string]*armpolicy.ParameterValuesValue{
					"setparameter1": {Value: "some-value"},
				},
			},
		})

		_ = az.AddPolicyAssignments(pa1, pa2)

		h := NewHierarchy(az)

		// Create mg1 with valid policy assignment.
		mg1 := &HierarchyManagementGroup{
			id:                    "mg1",
			hierarchy:             h,
			policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
			policyDefinitions:     make(map[string]*assets.PolicyDefinition),
			policySetDefinitions:  make(map[string]*assets.PolicySetDefinition),
			policyAssignments:     map[string]*assets.PolicyAssignment{*pa1.Name: pa1},
		}

		// Create mg2 with policy assignment that will trigger PolicyRoleAssignmentErrors
		// but still generate some valid role assignments from the policy set's role definition IDs.
		mg2 := &HierarchyManagementGroup{
			id:                    "mg2",
			hierarchy:             h,
			policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
			policyDefinitions:     make(map[string]*assets.PolicyDefinition),
			policySetDefinitions:  make(map[string]*assets.PolicySetDefinition),
			policyAssignments:     map[string]*assets.PolicyAssignment{*pa2.Name: pa2},
		}

		h.mgs["mg1"] = mg1
		h.mgs["mg2"] = mg2

		// Call PolicyRoleAssignments.
		res, err := h.PolicyRoleAssignments(context.Background())

		// Verify that we got a PolicyRoleAssignmentErrors.
		var policyRoleAssignmentErrs *PolicyRoleAssignmentErrors

		require.ErrorAs(t, err, &policyRoleAssignmentErrs, "expected PolicyRoleAssignmentErrors, got %T", err)

		// Verify that valid role assignments from mg1 are present.
		assert.True(t, res.Contains(PolicyRoleAssignment{
			AssignmentName:    *pa1.Name,
			RoleDefinitionID:  "/providers/Microsoft.Authorization/roleDefinitions/test-role-definition",
			Scope:             mg1.ResourceID(),
			ManagementGroupID: "mg1",
		}), "expected mg1 role assignment to be present")

		// Verify that valid role assignments from mg2 (from the policy set's roleDefinitionIds)
		// are also present, even though the ARM function parsing failed for the additional scope.
		assert.True(t, res.Contains(PolicyRoleAssignment{
			AssignmentName:    *pa2.Name,
			RoleDefinitionID:  "/providers/Microsoft.Authorization/roleDefinitions/test-role-definition2",
			Scope:             mg2.ResourceID(),
			ManagementGroupID: "mg2",
		}), "expected mg2 role assignment to be present despite errors")

		// Verify that we have at least 2 role assignments (one from each MG).
		assert.GreaterOrEqual(t, res.Cardinality(), 2, "expected at least 2 role assignments")
	})

	t.Run("returns all role assignments when no errors occur", func(t *testing.T) {
		t.Parallel()

		az := alzlib.NewAlzLib(nil)

		pd1 := assets.NewPolicyDefinition(armpolicy.Definition{
			Name: to.Ptr("test-policy-definition"),
			Properties: &armpolicy.DefinitionProperties{
				PolicyRule: map[string]any{
					"then": map[string]any{
						"details": map[string]any{
							"roleDefinitionIds": []any{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition"},
						},
					},
				},
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{},
			},
		})

		_ = az.AddPolicyDefinitions(pd1)

		pa1 := assets.NewPolicyAssignment(armpolicy.Assignment{
			Name:     to.Ptr("test-policy-assignment1"),
			Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
			Properties: &armpolicy.AssignmentProperties{
				PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition"),
			},
		})

		_ = az.AddPolicyAssignments(pa1)

		h := NewHierarchy(az)

		mg1 := &HierarchyManagementGroup{
			id:                    "mg1",
			hierarchy:             h,
			policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
			policyDefinitions:     make(map[string]*assets.PolicyDefinition),
			policySetDefinitions:  make(map[string]*assets.PolicySetDefinition),
			policyAssignments:     map[string]*assets.PolicyAssignment{*pa1.Name: pa1},
		}

		h.mgs["mg1"] = mg1

		res, err := h.PolicyRoleAssignments(context.Background())

		require.NoError(t, err)
		assert.Equal(t, 1, res.Cardinality())
		assert.True(t, res.Contains(PolicyRoleAssignment{
			AssignmentName:    *pa1.Name,
			RoleDefinitionID:  "/providers/Microsoft.Authorization/roleDefinitions/test-role-definition",
			Scope:             mg1.ResourceID(),
			ManagementGroupID: "mg1",
		}))
	})

	t.Run("returns non-PolicyRoleAssignmentErrors error without partial results", func(t *testing.T) {
		t.Parallel()

		az := alzlib.NewAlzLib(nil)

		// Create a policy assignment that references a non-existent policy definition.
		pa1 := assets.NewPolicyAssignment(armpolicy.Assignment{
			Name:     to.Ptr("test-policy-assignment1"),
			Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
			Properties: &armpolicy.AssignmentProperties{
				PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/non-existent-policy"),
			},
		})

		_ = az.AddPolicyAssignments(pa1)

		h := NewHierarchy(az)

		mg1 := &HierarchyManagementGroup{
			id:                    "mg1",
			hierarchy:             h,
			policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
			policyDefinitions:     make(map[string]*assets.PolicyDefinition),
			policySetDefinitions:  make(map[string]*assets.PolicySetDefinition),
			policyAssignments:     map[string]*assets.PolicyAssignment{*pa1.Name: pa1},
		}

		h.mgs["mg1"] = mg1

		res, err := h.PolicyRoleAssignments(context.Background())

		// Verify that we got a non-PolicyRoleAssignmentErrors error.
		require.Error(t, err)

		var policyRoleAssignmentErrs *PolicyRoleAssignmentErrors

		assert.NotErrorAs(t, err, &policyRoleAssignmentErrs, "expected non-PolicyRoleAssignmentErrors error")
		assert.Nil(t, res, "expected nil result on non-PolicyRoleAssignmentErrors error")
	})
}

func TestAddDefaultPolicyAssignmentValue(t *testing.T) {
	t.Parallel()

	pa1 := assets.NewPolicyAssignment(armpolicy.Assignment{
		Name: to.Ptr("pa1"),
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/policy1"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"param1": {
					Value: to.Ptr("changeme"),
				},
			},
		},
	})
	policy1 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("policy1"),
		Properties: &armpolicy.DefinitionProperties{
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"param1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
			},
		},
	})
	az := alzlib.NewAlzLib(nil)
	az.AddPolicyDefinitions(policy1) //nolint:errcheck
	az.AddPolicyAssignments(pa1)     //nolint:errcheck
	h := NewHierarchy(az)
	h.mgs["mg1"] = &HierarchyManagementGroup{
		policyAssignments: make(map[string]*assets.PolicyAssignment),
	}
	h.mgs["mg1"].policyAssignments["pa1"] = pa1
	h.mgs["mg1"].hierarchy = h

	// reflect set default value in alzlib
	defaultsNotSettable := reflect.ValueOf(az).Elem().FieldByName("defaultPolicyAssignmentValues")
	defaultsPtr := reflect.NewAt(defaultsNotSettable.Type(), (defaultsNotSettable.Addr().UnsafePointer())).
		Elem()
	defaults := defaultsPtr.Interface().(alzlib.DefaultPolicyAssignmentValues) //nolint:forcetypeassert

	t.Run("Default param present in definition", func(t *testing.T) {
		defaults.Add("default", "pa1", "", "param1")
		// Define the default policy assignment value.
		defaultName := "default"
		defaultValue := &armpolicy.ParameterValuesValue{Value: to.Ptr("value1")}
		// Add the default policy assignment value to the hierarchy.
		err := h.AddDefaultPolicyAssignmentValue(context.Background(), defaultName, defaultValue)
		require.NoError(t, err)
		// Verify that the default policy assignment value is added to the management group.
		assert.EqualValues(
			t,
			to.Ptr("value1"),
			h.mgs["mg1"].policyAssignments["pa1"].Properties.Parameters["param1"].Value,
		)
	})

	t.Run("Default parameter not present in definition", func(t *testing.T) {
		defaults.Add("default", "pa1", "", "param4")

		defaultName := "default"
		defaultValue := &armpolicy.ParameterValuesValue{Value: to.Ptr("value1")}
		// Add the default policy assignment value to the hierarchy.
		err := h.AddDefaultPolicyAssignmentValue(context.Background(), defaultName, defaultValue)
		require.Error(t, err)
	})
}
