// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/alzlib/processor"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
)

func TestNewAlzLibOptions(t *testing.T) {
	az := NewAlzLib(nil)
	assert.Equal(t, defaultParallelism, az.Options.Parallelism)
}

// Test_NewAlzLib_noDir tests the creation of a new AlzLib when supplied with a path
// that does not exist.
// The error details are checked for the expected error message.
func TestNewAlzLibWithNoDir(t *testing.T) {
	az := NewAlzLib(nil)
	path := filepath.Join("testdata", "doesnotexist")
	dir := os.DirFS(path)
	err := az.Init(context.Background(), dir)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// Test_NewAlzLibDuplicateArchetypeDefinition tests the creation of a new AlzLib from a invalid source directory.
func TestNewAlzLibDuplicateArchetypeDefinition(t *testing.T) {
	az := NewAlzLib(nil)
	dir := os.DirFS("./testdata/badlib-duplicatearchetypedef")
	err := az.Init(context.Background(), dir)
	assert.ErrorContains(t, err, "archetype with name `duplicate` already exists")
}

func TestGetBuiltInPolicy(t *testing.T) {
	az := NewAlzLib(nil)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	err = az.getBuiltInPolicies(context.Background(), []string{"8154e3b3-cc52-40be-9407-7756581d71f6"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.policyDefinitions))
	assert.Equal(t, "Microsoft Managed Control 1614 - Developer Security Architecture And Design", *az.policyDefinitions["8154e3b3-cc52-40be-9407-7756581d71f6"].Properties.DisplayName)
}

func TestGetBuiltInPolicySet(t *testing.T) {
	az := NewAlzLib(nil)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	err = az.getBuiltInPolicySets(context.Background(), []string{"7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.policySetDefinitions))
	assert.Equal(t, "Evaluate Private Link Usage Across All Supported Azure Resources", *az.policySetDefinitions["7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"].Properties.DisplayName)
	assert.Equal(t, 30, len(az.policyDefinitions))
}

func TestGenerateOverrideArchetypes(t *testing.T) {
	az := NewAlzLib(nil)

	// Create a base archetype
	baseArchetype := &Archetype{
		PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy1", "policy2"),
		PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet1", "policySet2"),
		PolicyAssignments:    mapset.NewThreadUnsafeSet("assignment1", "assignment2"),
		RoleDefinitions:      mapset.NewThreadUnsafeSet("role1", "role2"),
		name:                 "baseArchetype",
	}
	az.archetypes["baseArchetype"] = baseArchetype

	// Create a result with archetype overrides
	result := &processor.Result{
		LibArchetypeOverrides: map[string]*processor.LibArchetypeOverride{
			"overrideArchetype": {
				BaseArchetype:                "baseArchetype",
				PolicyDefinitionsToAdd:       mapset.NewThreadUnsafeSet("policy3"),
				PolicyDefinitionsToRemove:    mapset.NewThreadUnsafeSet("policy1"),
				PolicyAssignmentsToAdd:       mapset.NewThreadUnsafeSet("assignment3"),
				PolicyAssignmentsToRemove:    mapset.NewThreadUnsafeSet("assignment1"),
				PolicySetDefinitionsToAdd:    mapset.NewThreadUnsafeSet("policySet3"),
				PolicySetDefinitionsToRemove: mapset.NewThreadUnsafeSet("policySet1"),
				RoleDefinitionsToAdd:         mapset.NewThreadUnsafeSet("role3"),
				RoleDefinitionsToRemove:      mapset.NewThreadUnsafeSet("role1"),
			},
		},
	}
	az.policyAssignments["assignment1"] = nil
	az.policyAssignments["assignment2"] = nil
	az.policyAssignments["assignment3"] = nil
	az.policyDefinitions["policy1"] = nil
	az.policyDefinitions["policy2"] = nil
	az.policyDefinitions["policy3"] = nil
	az.policySetDefinitions["policySet1"] = nil
	az.policySetDefinitions["policySet2"] = nil
	az.policySetDefinitions["policySet3"] = nil
	az.roleDefinitions["role1"] = nil
	az.roleDefinitions["role2"] = nil
	az.roleDefinitions["role3"] = nil
	err := az.generateOverrideArchetypes(result)
	assert.NoError(t, err)

	// Check if the override archetype is created correctly
	overrideArchetype, exists := az.archetypes["overrideArchetype"]
	assert.True(t, exists)
	assert.True(t, mapset.NewThreadUnsafeSet("policy2", "policy3").Equal(overrideArchetype.PolicyDefinitions))
	assert.True(t, mapset.NewThreadUnsafeSet("policySet2", "policySet3").Equal(overrideArchetype.PolicySetDefinitions))
	assert.True(t, mapset.NewThreadUnsafeSet("assignment2", "assignment3").Equal(overrideArchetype.PolicyAssignments))
	assert.True(t, mapset.NewThreadUnsafeSet("role2", "role3").Equal(overrideArchetype.RoleDefinitions))
	assert.Equal(t, "overrideArchetype", overrideArchetype.name)
}

func TestGenerateArchitectures(t *testing.T) {
	az := NewAlzLib(nil)
	az.architectures = make(map[string]*Architecture)
	az.archetypes["archetype1"] = &Archetype{
		PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy1"),
		PolicyAssignments:    mapset.NewThreadUnsafeSet("assignment1"),
		PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet1"),
		RoleDefinitions:      mapset.NewThreadUnsafeSet("role1"),
		name:                 "archetype1",
	}
	az.archetypes["archetype2"] = &Archetype{
		PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy2"),
		PolicyAssignments:    mapset.NewThreadUnsafeSet("assignment2"),
		PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet2"),
		RoleDefinitions:      mapset.NewThreadUnsafeSet("role2"),
		name:                 "archetype2",
	}
	res := &processor.Result{
		LibArchitectures: map[string]*processor.LibArchitecture{
			"architecture1": {
				Name: "architecture1",
				ManagementGroups: []processor.LibArchitectureManagementGroup{
					{
						Id:          "mg1",
						ParentId:    nil,
						Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
						DisplayName: "mg1",
						Exists:      false,
					},
					{
						Id:          "mg2",
						ParentId:    to.Ptr("mg1"),
						Archetypes:  mapset.NewThreadUnsafeSet("archetype2"),
						DisplayName: "mg2",
						Exists:      false,
					},
				},
			},
		},
	}
	err := az.generateArchitectures(res)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.architectures))
	assert.NotNil(t, az.architectures["architecture1"])
}

func TestGenerateArchitecturesTbt(t *testing.T) {
	testCases := []struct {
		name            string
		setupAlzLib     func(az *AlzLib)
		expectedLength  int
		expectedNotNil  string
		processorOutput *processor.Result
	}{
		{
			name: "single architecture with two management groups",
			setupAlzLib: func(az *AlzLib) {
				az.archetypes["archetype1"] = &Archetype{
					PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy1"),
					PolicyAssignments:    mapset.NewThreadUnsafeSet("assignment1"),
					PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet1"),
					RoleDefinitions:      mapset.NewThreadUnsafeSet("role1"),
					name:                 "archetype1",
				}
				az.archetypes["archetype2"] = &Archetype{
					PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy2"),
					PolicyAssignments:    mapset.NewThreadUnsafeSet("assignment2"),
					PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet2"),
					RoleDefinitions:      mapset.NewThreadUnsafeSet("role2"),
					name:                 "archetype2",
				}
				az.architectures = make(map[string]*Architecture)
			},
			processorOutput: &processor.Result{
				LibArchitectures: map[string]*processor.LibArchitecture{
					"architecture1": {
						Name: "architecture1",
						ManagementGroups: []processor.LibArchitectureManagementGroup{
							{
								Id:          "mg1",
								ParentId:    nil,
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "mg1",
								Exists:      false,
							},
							{
								Id:          "mg2",
								ParentId:    to.Ptr("mg1"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype2"),
								DisplayName: "mg2",
								Exists:      false,
							},
						},
					},
				},
			},
			expectedLength: 1,
			expectedNotNil: "architecture1",
		},
		// Add more test cases here
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			az := NewAlzLib(nil)
			tc.setupAlzLib(az)

			err := az.generateArchitectures(tc.processorOutput)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedLength, len(az.architectures))
			assert.NotNil(t, az.architectures[tc.expectedNotNil])
		})
	}
}
