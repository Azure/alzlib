// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/alzlib/pkg/processor"
	"github.com/Azure/alzlib/pkg/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestGenerateArchitecturesTbt(t *testing.T) {
	testCases := []struct {
		name            string
		setupAlzLib     func(az *AlzLib)
		expectedLength  int
		expectedError   string
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
			expectedError:  "",
			expectedLength: 1,
			expectedNotNil: "architecture1",
		},
		{
			name: "single architecture with two management groups and incorrect parent",
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
								ParentId:    to.Ptr("notexist"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype2"),
								DisplayName: "mg2",
								Exists:      false,
							},
						},
					},
				},
			},
			expectedError:  "",
			expectedLength: 1,
			expectedNotNil: "architecture1",
		},
		{
			name: "single architecture with no management groups",
			setupAlzLib: func(az *AlzLib) {
				az.archetypes["archetype1"] = &Archetype{
					PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy1"),
					PolicyAssignments:    mapset.NewThreadUnsafeSet("assignment1"),
					PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet1"),
					RoleDefinitions:      mapset.NewThreadUnsafeSet("role1"),
					name:                 "archetype1",
				}
				az.architectures = make(map[string]*Architecture)
			},
			processorOutput: &processor.Result{
				LibArchitectures: map[string]*processor.LibArchitecture{
					"architecture1": {
						Name:             "architecture1",
						ManagementGroups: []processor.LibArchitectureManagementGroup{},
					},
				},
			},
			expectedError:  "architectureRecursion: no management groups found",
			expectedLength: 1,
			expectedNotNil: "architecture1",
		},
		{
			name: "multiple architectures with management groups",
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
					"architecture2": {
						Name: "architecture2",
						ManagementGroups: []processor.LibArchitectureManagementGroup{
							{
								Id:          "mg3",
								ParentId:    nil,
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1", "archetype2"),
								DisplayName: "mg3",
								Exists:      false,
							},
						},
					},
				},
			},
			expectedError:  "",
			expectedLength: 2,
			expectedNotNil: "architecture1",
		},
		{
			name: "management group hierarchy too deep",
			setupAlzLib: func(az *AlzLib) {
				az.archetypes["archetype1"] = &Archetype{
					PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy1"),
					PolicyAssignments:    mapset.NewThreadUnsafeSet("assignment1"),
					PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet1"),
					RoleDefinitions:      mapset.NewThreadUnsafeSet("role1"),
					name:                 "archetype1",
				}
			},
			processorOutput: &processor.Result{
				LibArchitectures: map[string]*processor.LibArchitecture{
					"toodeep": {
						Name: "toodeep",
						ManagementGroups: []processor.LibArchitectureManagementGroup{
							{
								Id:          "level0",
								ParentId:    nil,
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level0",
								Exists:      false,
							},
							{
								Id:          "level1",
								ParentId:    to.Ptr("level0"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level0",
								Exists:      false,
							},
							{
								Id:          "level2",
								ParentId:    to.Ptr("level1"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level2",
								Exists:      false,
							},
							{
								Id:          "level3",
								ParentId:    to.Ptr("level2"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level3",
								Exists:      false,
							},
							{
								Id:          "level4",
								ParentId:    to.Ptr("level3"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level4",
								Exists:      false,
							},
							{
								Id:          "level5",
								ParentId:    to.Ptr("level4"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level5",
								Exists:      false,
							},
							{
								Id:          "level6",
								ParentId:    to.Ptr("level5"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level6",
								Exists:      false,
							},
						},
					},
				},
			},
			expectedLength: 1,
			expectedNotNil: "toodeep",
			expectedError:  "architectureRecursion: recursion depth exceeded",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			az := NewAlzLib(nil)
			tc.setupAlzLib(az)

			err := az.generateArchitectures(tc.processorOutput)
			if tc.expectedError == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedLength, len(az.architectures))
				assert.NotNil(t, az.architectures[tc.expectedNotNil])
			} else {
				assert.ErrorContains(t, err, tc.expectedError)
			}
		})
	}
}

func TestFetchLibraryByGetterString(t *testing.T) {
	ctx := context.Background()
	dstDir := "test-library"
	defer os.RemoveAll(filepath.Join(".alzlib", dstDir))

	fs, err := FetchLibraryByGetterString(ctx, "./testdata/simple", dstDir)
	assert.NoError(t, err)
	assert.NotNil(t, fs)
}

func TestAddDefaultPolicyValues(t *testing.T) {
	az := NewAlzLib(nil)
	res := &processor.Result{
		LibDefaultPolicyValues: map[string]*processor.LibDefaultPolicyValuesDefaults{
			"default1": {
				PolicyAssignments: []processor.LibDefaultPolicyValueAssignments{
					{
						PolicyAssignmentName: "assignment1",
						ParameterNames:       []string{"param1", "param2"},
					},
				},
			},
		},
	}

	err := az.addDefaultPolicyAssignmentValues(res)
	assert.NoError(t, err)

	// Check if the default policy values are added correctly
	assert.Equal(t, 1, len(az.defaultPolicyAssignmentValues))
	assert.Equal(t, 1, len(az.defaultPolicyAssignmentValues["default1"]))
	assert.True(t, az.defaultPolicyAssignmentValues["default1"]["assignment1"].Contains("param1"))
	assert.True(t, az.defaultPolicyAssignmentValues["default1"]["assignment1"].Contains("param2"))
	assert.True(t, az.defaultPolicyAssignmentValues.AssignmentParameterComboExists("assignment1", "param2"))

	res = &processor.Result{
		LibDefaultPolicyValues: map[string]*processor.LibDefaultPolicyValuesDefaults{
			"default1": {
				PolicyAssignments: []processor.LibDefaultPolicyValueAssignments{
					{
						PolicyAssignmentName: "assignment1",
						ParameterNames:       []string{"param1", "param2"},
					},
				},
			},
			"default2": {
				PolicyAssignments: []processor.LibDefaultPolicyValueAssignments{
					{
						PolicyAssignmentName: "assignment1",
						ParameterNames:       []string{"param1", "param2"},
					},
				},
			},
		},
	}
	az = NewAlzLib(nil)
	err = az.addDefaultPolicyAssignmentValues(res)
	assert.ErrorContains(t, err, "assignment `assignment1` and parameter `param1` already exists in defaults")
}

func TestInitSimple(t *testing.T) {
	az := NewAlzLib(nil)
	ctx := context.Background()
	dirfs := os.DirFS("./testdata/simple")
	require.NoError(t, az.Init(ctx, dirfs))
	assert.Equal(t, []string{"empty", "simple", "simpleoverride"}, az.Archetypes())
	assert.Equal(t, []string{"test-policy-definition"}, az.PolicyDefinitions())
	assert.Equal(t, []string{"test-policy-set-definition"}, az.PolicySetDefinitions())
	assert.Equal(t, []string{"test-role-definition"}, az.RoleDefinitions())
	assert.Equal(t, []string{"override-policy-assignment", "test-policy-assignment"}, az.PolicyAssignments())
	assert.Equal(t, []string{"test"}, az.PolicyDefaultValues())
}
