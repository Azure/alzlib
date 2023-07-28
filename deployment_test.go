package alzlib

import (
	"context"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWellKnownParameterReplacement demonstrates the replacement of well-known parameters.
func TestWellKnownParameterReplacement(t *testing.T) {
	t.Parallel()
	az := NewAlzLib()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirfs := os.DirFS("./testdata/wellknownparameters")
	err := az.Init(ctx, dirfs)
	require.NoError(t, err)

	vals := &WellKnownPolicyValues{
		DefaultLocation:                "eastus",
		DefaultLogAnalyticsWorkspaceId: "testlaworkspaceid",
	}

	arch, err := az.CopyArchetype("test", vals)
	assert.NoError(t, err)
	assert.NoError(t, az.AddManagementGroupToDeployment("test", "test", "external", true, arch))

	paramValue := az.Deployment.mgs["test"].policyAssignments["Deploy-AzActivity-Log"].Properties.Parameters["logAnalytics"].Value
	assert.Equal(t, "testlaworkspaceid", paramValue)
}

func TestPolicySetDefinitionToMg(t *testing.T) {
	t.Parallel()
	// Test with a single management group and policy set definition.
	d := DeploymentType{
		mgs: map[string]*AlzManagementGroup{
			"mg1": {
				policySetDefinitions: map[string]*armpolicy.SetDefinition{
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
	d = DeploymentType{
		mgs: map[string]*AlzManagementGroup{
			"mg1": {
				policySetDefinitions: map[string]*armpolicy.SetDefinition{
					"psd1": {},
				},
			},
			"mg2": {
				policySetDefinitions: map[string]*armpolicy.SetDefinition{
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
	d = DeploymentType{}
	expected = map[string]string{}
	assert.Equal(t, expected, d.policySetDefinitionToMg())
}

func TestPolicyDefinitionToMg(t *testing.T) {
	t.Parallel()
	// Test with a single management group and policy definition.
	d := DeploymentType{
		mgs: map[string]*AlzManagementGroup{
			"mg1": {
				policyDefinitions: map[string]*armpolicy.Definition{
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
	d = DeploymentType{
		mgs: map[string]*AlzManagementGroup{
			"mg1": {
				policyDefinitions: map[string]*armpolicy.Definition{
					"pd1": {},
				},
			},
			"mg2": {
				policyDefinitions: map[string]*armpolicy.Definition{
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
	d = DeploymentType{}
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
