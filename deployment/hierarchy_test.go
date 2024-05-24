// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"testing"

	"github.com/Azure/alzlib/assets"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestPolicySetDefinitionToMg(t *testing.T) {
	t.Parallel()
	// Test with a single management group and policy set definition.
	d := Hierarchy{
		mgs: map[string]*ManagementGroup{
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
		mgs: map[string]*ManagementGroup{
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
		mgs: map[string]*ManagementGroup{
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
		mgs: map[string]*ManagementGroup{
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
