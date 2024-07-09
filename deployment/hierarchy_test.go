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
	expected := map[string]string{
		"psd1": "mg1",
	}
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
	expected = map[string]string{
		"psd1": "mg1",
		"psd2": "mg2",
		"psd3": "mg2",
	}
	assert.Equal(t, expected, d.policySetDefinitionToMg())

	// Test with no management groups or policy set definitions.
	d = Hierarchy{}
	expected = map[string]string{}
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
	expected := map[string]string{
		"pd1": "mg1",
	}
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
	expected = map[string]string{
		"pd1": "mg1",
		"pd2": "mg2",
		"pd3": "mg2",
	}
	assert.Equal(t, expected, d.policyDefinitionToMg())

	// Test with no management groups or policy definitions.
	d = Hierarchy{}
	expected = map[string]string{}
	assert.Equal(t, expected, d.policyDefinitionToMg())
}

func TestNewUUID(t *testing.T) {
	t.Parallel()
	// create a new UUID namespace.
	ns := uuid.MustParse("d97506b3-4470-5694-a203-2c37e477d3ac")

	u := uuidV5("foo", "bar", "baz")

	assert.Equal(t, ns.String(), u.String())
}

func TestAddDefaultPolicyAssignmentValue(t *testing.T) {
	t.Parallel()

	pa1 := assets.NewPolicyAssignment(armpolicy.Assignment{
		Name: to.Ptr("pa1"),
		Properties: &armpolicy.AssignmentProperties{
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"param1": {
					Value: to.Ptr("changeme"),
				},
			},
		},
	})
	az := alzlib.NewAlzLib(nil)
	az.AddPolicyAssignments(pa1) //nolint:errcheck
	h := NewHierarchy(az)
	h.mgs["mg1"] = &HierarchyManagementGroup{
		policyAssignments: make(map[string]*assets.PolicyAssignment),
	}
	h.mgs["mg1"].policyAssignments["pa1"] = pa1

	// reflect set default value in alzlib
	defaultsNotSettable := reflect.ValueOf(az).Elem().FieldByName("defaultPolicyAssignmentValues")
	defaultsPtr := reflect.NewAt(defaultsNotSettable.Type(), (defaultsNotSettable.Addr().UnsafePointer())).Elem()
	defaults := defaultsPtr.Interface().(alzlib.DefaultPolicyAssignmentValues) //nolint:forcetypeassert
	defaults["default"] = make(alzlib.DefaultPolicyAssignmentValuesValue)
	defaults["default"]["pa1"] = mapset.NewThreadUnsafeSet("param4")

	// Define the default policy assignment value.
	defaultName := "default"
	defaultValue := &armpolicy.ParameterValuesValue{Value: to.Ptr("value1")}

	// Add the default policy assignment value to the hierarchy.
	err := h.AddDefaultPolicyAssignmentValue(context.Background(), defaultName, defaultValue)
	assert.NoError(t, err)

	// Verify that the default policy assignment value is added to the management group.
	assert.EqualValues(t, to.Ptr("value1"), h.mgs["mg1"].policyAssignments["pa1"].Properties.Parameters["param1"].Value)
}
