// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/internal/auth"
	"github.com/Azure/alzlib/internal/processor"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	corepolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAlzLibDefaultOptions(t *testing.T) {
	az := NewAlzLib(nil)
	assert.Equal(t, defaultOverwrite, az.Options.AllowOverwrite)
	assert.Equal(t, defaultParallelism, az.Options.Parallelism)
	assert.Equal(t, defaultUniqueRoleDefinitions, az.Options.UniqueRoleDefinitions)
}

func TestNewAlzLibCustomOptions(t *testing.T) {
	az := NewAlzLib(&Options{
		AllowOverwrite:        true,
		Parallelism:           25,
		UniqueRoleDefinitions: false,
	})
	assert.True(t, az.Options.AllowOverwrite)
	assert.Equal(t, 25, az.Options.Parallelism)
	assert.False(t, az.Options.UniqueRoleDefinitions)
}

func TestAddPolicyAndRoleAssetsAllowsDuplicateVersions(t *testing.T) {
	testCases := []struct {
		name           string
		allowOverwrite bool
	}{
		{name: "disallow overwrite", allowOverwrite: false},
		{name: "allow overwrite", allowOverwrite: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			az := NewAlzLib(&Options{
				AllowOverwrite:        tc.allowOverwrite,
				Parallelism:           defaultParallelism,
				UniqueRoleDefinitions: defaultUniqueRoleDefinitions,
			})

			// We prime the alzlib with an existing policy and policy set definition
			// that has the same name and version as those being added in the processor result.
			// This tests that **IDENTICAL** duplicate versions are allowed regardless of the AllowOverwrite setting.
			existingPolicyDefs := assets.NewPolicyDefinitionVersions()
			require.NoError(t, existingPolicyDefs.Add(testPolicyDefinition(t, "dup-policy", "1.0.0"), false))
			az.policyDefinitions["dup-policy"] = existingPolicyDefs

			existingPolicySetDefs := assets.NewPolicySetDefinitionVersions()
			require.NoError(t, existingPolicySetDefs.Add(testPolicySetDefinition(t, "dup-policy-set", "1.0.0"), false))
			az.policySetDefinitions["dup-policy-set"] = existingPolicySetDefs

			res := processor.NewResult()
			dupPolicyDefsIdenical := assets.NewPolicyDefinitionVersions()
			require.NoError(t, dupPolicyDefsIdenical.Add(testPolicyDefinition(t, "dup-policy", "1.0.0"), false))
			res.PolicyDefinitions["dup-policy"] = dupPolicyDefsIdenical

			dupPolicySetDefsIdentical := assets.NewPolicySetDefinitionVersions()
			require.NoError(t, dupPolicySetDefsIdentical.Add(testPolicySetDefinition(t, "dup-policy-set", "1.0.0"), false))
			res.PolicySetDefinitions["dup-policy-set"] = dupPolicySetDefsIdentical

			require.NoError(t, az.addPolicyAndRoleAssets(res))

			// Now we attempt to add duplicate versions that are different.
			dupPolicyDefsDifferent := assets.NewPolicyDefinitionVersions()
			testPd := testPolicyDefinition(t, "dup-policy", "1.0.0")
			testPd.Properties.Description = to.Ptr("A different description to make this policy definition different")
			require.NoError(t, dupPolicyDefsDifferent.Add(testPd, false))

			res = processor.NewResult()
			res.PolicyDefinitions["dup-policy"] = dupPolicyDefsDifferent

			switch tc.allowOverwrite {
			case true:
				require.NoError(t, az.addPolicyAndRoleAssets(res))
			case false:
				require.Error(t, az.addPolicyAndRoleAssets(res))
			}
		})
	}
}

// Test_NewAlzLib_noDir tests the creation of a new AlzLib when supplied with a path
// that does not exist.
// The error details are checked for the expected error message.
func TestNewAlzLibWithNoDir(t *testing.T) {
	az := NewAlzLib(nil)
	path := filepath.Join("testdata", "doesnotexist")
	lib := NewCustomLibraryReference(path)
	err := az.Init(context.Background(), lib)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// Test_NewAlzLibDuplicateArchetypeDefinition tests the creation of a new AlzLib from a invalid
// source directory.
func TestNewAlzLibDuplicateArchetypeDefinition(t *testing.T) {
	az := NewAlzLib(nil)
	lib := NewCustomLibraryReference("./testdata/badlib-duplicatearchetypedef")
	err := az.Init(context.Background(), lib)
	require.ErrorContains(t, err, "archetype with name `duplicate` already exists")
}

func TestGetBuiltInPolicy(t *testing.T) {
	az := NewAlzLib(nil)
	cred, err := auth.NewToken()
	require.NoError(t, err)

	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)

	resId, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/8154e3b3-cc52-40be-9407-7756581d71f6")
	require.NoError(t, err)
	err = az.getBuiltInPolicies(
		context.Background(),
		[]BuiltInRequest{
			{
				ResourceID: resId,
				Version:    nil,
			},
		},
	)
	require.NoError(t, err)
	assert.Len(t, az.policyDefinitions, 1)
	assert.Equal(
		t,
		"Microsoft Managed Control 1614 - Developer Security Architecture And Design",
		*az.PolicyDefinition("8154e3b3-cc52-40be-9407-7756581d71f6", nil).Properties.DisplayName,
	)
}

func TestListAllBuiltIns(t *testing.T) {
	cred, err := auth.NewToken()
	require.NoError(t, err)

	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	cli := cf.NewSetDefinitionVersionsClient()
	pg := cli.NewListBuiltInPager("7379ef4c-89b0-48b6-a5cc-fd3a75eaef93", &armpolicy.SetDefinitionVersionsClientListBuiltInOptions{
		Expand: to.Ptr("LatestDefinitionVersion, EffectiveDefinitionVersion"),
		Top:    to.Ptr[int32](500),
	})
	pdvc := assets.NewPolicySetDefinitionVersions()

	for pg.More() {
		page, err := pg.NextPage(t.Context())
		require.NoError(t, err)

		for _, v := range page.Value {
			pdv, err := assets.NewPolicySetDefinitionFromVersionValidate(*v)
			require.NoError(t, err)
			require.NoError(t, pdvc.Add(pdv, false))
		}
	}

	res, err := pdvc.GetVersion(to.Ptr("1.*.*"))
	require.NoError(t, err)
	require.NotNil(t, res.Properties.Version)
	assert.Equal(t, "1.2.0", *res.Properties.Version)
}

func TestGetBuiltInPolicySet(t *testing.T) {
	az := NewAlzLib(nil)
	cred, err := auth.NewToken()
	require.NoError(t, err)

	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)

	resId, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/7379ef4c-89b0-48b6-a5cc-fd3a75eaef93")
	require.NoError(t, err)
	err = az.getBuiltInPolicySets(
		context.Background(),
		[]BuiltInRequest{
			{
				ResourceID: resId,
				Version:    nil,
			},
		},
	)
	require.NoError(t, err)
	assert.Len(t, az.policySetDefinitions, 1)
	assert.Equal(
		t,
		"Evaluate Private Link Usage Across All Supported Azure Resources",
		*az.PolicySetDefinition("7379ef4c-89b0-48b6-a5cc-fd3a75eaef93", nil).Properties.DisplayName,
	)
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
	require.NoError(t, err)

	// Check if the override archetype is created correctly
	overrideArchetype, exists := az.archetypes["overrideArchetype"]
	assert.True(t, exists)
	assert.True(
		t,
		mapset.NewThreadUnsafeSet("policy2", "policy3").Equal(overrideArchetype.PolicyDefinitions),
	)
	assert.True(
		t,
		mapset.NewThreadUnsafeSet("policySet2", "policySet3").
			Equal(overrideArchetype.PolicySetDefinitions),
	)
	assert.True(
		t,
		mapset.NewThreadUnsafeSet("assignment2", "assignment3").
			Equal(overrideArchetype.PolicyAssignments),
	)
	assert.True(
		t,
		mapset.NewThreadUnsafeSet("role2", "role3").Equal(overrideArchetype.RoleDefinitions),
	)
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
								ID:          "mg1",
								ParentID:    nil,
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "mg1",
								Exists:      false,
							},
							{
								ID:          "mg2",
								ParentID:    to.Ptr("mg1"),
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
								ID:          "mg1",
								ParentID:    nil,
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "mg1",
								Exists:      false,
							},
							{
								ID:          "mg2",
								ParentID:    to.Ptr("notexist"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype2"),
								DisplayName: "mg2",
								Exists:      false,
							},
						},
					},
				},
			},
			expectedError:  "invalid parent",
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
								ID:          "mg1",
								ParentID:    nil,
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "mg1",
								Exists:      false,
							},
							{
								ID:          "mg2",
								ParentID:    to.Ptr("mg1"),
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
								ID:          "mg3",
								ParentID:    nil,
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
								ID:          "level0",
								ParentID:    nil,
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level0",
								Exists:      false,
							},
							{
								ID:          "level1",
								ParentID:    to.Ptr("level0"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level0",
								Exists:      false,
							},
							{
								ID:          "level2",
								ParentID:    to.Ptr("level1"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level2",
								Exists:      false,
							},
							{
								ID:          "level3",
								ParentID:    to.Ptr("level2"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level3",
								Exists:      false,
							},
							{
								ID:          "level4",
								ParentID:    to.Ptr("level3"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level4",
								Exists:      false,
							},
							{
								ID:          "level5",
								ParentID:    to.Ptr("level4"),
								Archetypes:  mapset.NewThreadUnsafeSet("archetype1"),
								DisplayName: "level5",
								Exists:      false,
							},
							{
								ID:          "level6",
								ParentID:    to.Ptr("level5"),
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
				require.NoError(t, err)
				assert.Len(t, az.architectures, tc.expectedLength)
				assert.NotNil(t, az.architectures[tc.expectedNotNil])
			} else {
				require.ErrorContains(t, err, tc.expectedError)
			}
		})
	}
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
	require.NoError(t, err)

	// Check if the default policy values are added correctly
	assert.Len(t, az.defaultPolicyAssignmentValues, 1)
	assert.Len(t, az.defaultPolicyAssignmentValues["default1"].assignment2Parameters, 1)
	assert.True(
		t,
		az.defaultPolicyAssignmentValues["default1"].assignment2Parameters["assignment1"].Contains(
			"param1",
		),
	)
	assert.True(
		t,
		az.defaultPolicyAssignmentValues["default1"].assignment2Parameters["assignment1"].Contains(
			"param2",
		),
	)
	assert.True(
		t,
		az.defaultPolicyAssignmentValues.AssignmentParameterComboExists("assignment1", "param2"),
	)

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
	require.ErrorContains(
		t,
		err,
		"assignment `assignment1` and parameter `param1` already exists in defaults",
	)
}

func TestInitSimple(t *testing.T) {
	az := NewAlzLib(nil)
	ctx := context.Background()
	lib := NewCustomLibraryReference("./testdata/simple")
	require.NoError(t, az.Init(ctx, lib))
	assert.Equal(t, []string{"empty", "simple", "simpleoverride"}, az.Archetypes())
	assert.Equal(t, []string{"test-policy-definition"}, az.PolicyDefinitions())
	assert.Equal(t, []string{"test-policy-set-definition"}, az.PolicySetDefinitions())
	assert.Equal(t, []string{"test-role-definition"}, az.RoleDefinitions())
	assert.Equal(t, []string{"override-pa", "test-pa"}, az.PolicyAssignments())
	assert.Equal(t, []string{"test"}, az.PolicyDefaultValues())
}

func TestPolicyDefinitionExistsWithVersion(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create a versioned policy definition
	pd := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("1.0.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
		},
	})

	err := az.AddPolicyDefinitions(pd)
	require.NoError(t, err)

	// Test existence with version constraint matching 1.0.0
	assert.True(t, az.PolicyDefinitionExists("testPolicy", to.Ptr("1.0.*")))

	// Test existence with nil version (latest)
	assert.True(t, az.PolicyDefinitionExists("testPolicy", nil))

	// Test existence with non-existent version constraint
	assert.False(t, az.PolicyDefinitionExists("testPolicy", to.Ptr("2.0.*")))

	// Test existence with non-existent policy
	assert.False(t, az.PolicyDefinitionExists("nonExistent", nil))
}

func TestPolicySetDefinitionExistsWithVersion(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create a versioned policy set definition
	psd := assets.NewPolicySetDefinition(armpolicy.SetDefinition{
		Name: to.Ptr("testPolicySet"),
		Properties: &armpolicy.SetDefinitionProperties{
			Version:           to.Ptr("2.1.0"),
			PolicyType:        to.Ptr(armpolicy.PolicyTypeCustom),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
		},
	})

	err := az.AddPolicySetDefinitions(psd)
	require.NoError(t, err)

	// Test existence with version constraint matching 2.1.0
	assert.True(t, az.PolicySetDefinitionExists("testPolicySet", to.Ptr("2.1.*")))

	// Test existence with nil version (latest)
	assert.True(t, az.PolicySetDefinitionExists("testPolicySet", nil))

	// Test existence with non-existent version constraint
	assert.False(t, az.PolicySetDefinitionExists("testPolicySet", to.Ptr("1.0.*")))

	// Test existence with non-existent policy set
	assert.False(t, az.PolicySetDefinitionExists("nonExistent", nil))
}

func TestPolicyDefinitionGetWithVersion(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Add two versions of the same policy
	pd1 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("1.0.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{"rule": "v1"},
			Metadata:   map[string]any{"version": "1.0.0"},
		},
	})

	pd2 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("2.0.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{"rule": "v2"},
			Metadata:   map[string]any{"version": "2.0.0"},
		},
	})

	require.NoError(t, az.AddPolicyDefinitions(pd1))
	require.NoError(t, az.AddPolicyDefinitions(pd2))

	// Get version 1.0.0 using constraint
	result1 := az.PolicyDefinition("testPolicy", to.Ptr("1.0.*"))
	require.NotNil(t, result1)
	assert.Equal(t, "1.0.0", *result1.Properties.Version)

	// Get version 2.0.0 using constraint
	result2 := az.PolicyDefinition("testPolicy", to.Ptr("2.0.*"))
	require.NotNil(t, result2)
	assert.Equal(t, "2.0.0", *result2.Properties.Version)

	// Get latest (nil version) - should return 2.0.0
	resultLatest := az.PolicyDefinition("testPolicy", nil)
	require.NotNil(t, resultLatest)
	assert.Equal(t, "2.0.0", *resultLatest.Properties.Version)

	// Get non-existent policy
	resultNil := az.PolicyDefinition("nonExistent", nil)
	assert.Nil(t, resultNil)
}

func TestPolicySetDefinitionGetWithVersion(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Add two versions of the same policy set
	psd1 := assets.NewPolicySetDefinition(armpolicy.SetDefinition{
		Name: to.Ptr("testPolicySet"),
		Properties: &armpolicy.SetDefinitionProperties{
			Version:           to.Ptr("1.5.0"),
			PolicyType:        to.Ptr(armpolicy.PolicyTypeCustom),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
			Metadata:          map[string]any{"version": "1.5.0"},
		},
	})

	psd2 := assets.NewPolicySetDefinition(armpolicy.SetDefinition{
		Name: to.Ptr("testPolicySet"),
		Properties: &armpolicy.SetDefinitionProperties{
			Version:           to.Ptr("1.6.0"),
			PolicyType:        to.Ptr(armpolicy.PolicyTypeCustom),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
			Metadata:          map[string]any{"version": "1.6.0"},
		},
	})

	require.NoError(t, az.AddPolicySetDefinitions(psd1))
	require.NoError(t, az.AddPolicySetDefinitions(psd2))

	// Get version 1.5.0 using constraint
	result1 := az.PolicySetDefinition("testPolicySet", to.Ptr("1.5.*"))
	require.NotNil(t, result1)
	assert.Equal(t, "1.5.0", *result1.Properties.Version)

	// Get version 1.6.0 using constraint
	result2 := az.PolicySetDefinition("testPolicySet", to.Ptr("1.6.*"))
	require.NotNil(t, result2)
	assert.Equal(t, "1.6.0", *result2.Properties.Version)

	// Get latest (nil version) - should return 1.6.0
	resultLatest := az.PolicySetDefinition("testPolicySet", nil)
	require.NotNil(t, resultLatest)
	assert.Equal(t, "1.6.0", *resultLatest.Properties.Version)

	// Get non-existent policy set
	resultNil := az.PolicySetDefinition("nonExistent", nil)
	assert.Nil(t, resultNil)
}

func TestSetAssignPermissionsOnDefinitionParameter(t *testing.T) {
	t.Parallel()

	// Create a policy definition with a parameter
	pd := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("1.0.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"testParam": {
					Type:     to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{},
				},
			},
		},
	})

	pd2 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy2"),
		Properties: &armpolicy.DefinitionProperties{
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"testParam": {
					Type:     to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{},
				},
			},
		},
	})

	tc := []struct {
		name                      string
		def                       *assets.PolicyDefinition
		versionConstraint         *string
		paramName                 string
		expectedAssignPermissions bool
	}{
		{
			name:                      "versioned policy",
			def:                       pd,
			versionConstraint:         to.Ptr("1.0.*"),
			paramName:                 "testParam",
			expectedAssignPermissions: true,
		},
		{
			name:                      "versionless policy",
			def:                       pd2,
			paramName:                 "testParam",
			expectedAssignPermissions: true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create a policy definition with a parameter
			az := NewAlzLib(nil)
			require.NoError(t, az.AddPolicyDefinitions(tt.def))
			az.SetAssignPermissionsOnDefinitionParameter(*tt.def.Name, tt.paramName)
			result := az.PolicyDefinition(*tt.def.Name, tt.versionConstraint)
			require.NotNil(t, result)
			param := result.Parameter(tt.paramName)
			require.NotNil(t, param)
			require.NotNil(t, param.Metadata)
			require.NotNil(t, param.Metadata.AssignPermissions)
			assert.Equal(t, tt.expectedAssignPermissions, *param.Metadata.AssignPermissions)
		})
	}
}

func TestUnsetAssignPermissionsOnDefinitionParameter(t *testing.T) {
	t.Parallel()

	// Create a policy definition with a parameter
	pd := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("1.0.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"testParam": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(true),
					},
				},
			},
		},
	})

	pd2 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy2"),
		Properties: &armpolicy.DefinitionProperties{
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"testParam": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(true),
					},
				},
			},
		},
	})

	tc := []struct {
		name                      string
		def                       *assets.PolicyDefinition
		versionConstraint         *string
		paramName                 string
		expectedAssignPermissions bool
	}{
		{
			name:              "versioned policy",
			def:               pd,
			versionConstraint: to.Ptr("1.0.*"),
			paramName:         "testParam",
		},
		{
			name:      "versionless policy",
			def:       pd2,
			paramName: "testParam",
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create a policy definition with a parameter
			az := NewAlzLib(nil)
			require.NoError(t, az.AddPolicyDefinitions(tt.def))
			az.UnsetAssignPermissionsOnDefinitionParameter(*tt.def.Name, tt.paramName)
			result := az.PolicyDefinition(*tt.def.Name, tt.versionConstraint)
			require.NotNil(t, result)
			param := result.Parameter(tt.paramName)
			require.NotNil(t, param)
			require.NotNil(t, param.Metadata)
			assert.Nil(t, param.Metadata.AssignPermissions)
		})
	}
}

func TestAssignmentReferencedDefinitionHasParameter(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create a policy definition with parameters
	pd := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("1.0.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"existingParam": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
			},
		},
	})

	require.NoError(t, az.AddPolicyDefinitions(pd))

	resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/testPolicy")
	require.NoError(t, err)

	// Test with existing parameter using version constraint
	assert.True(t, az.AssignmentReferencedDefinitionHasParameter(resID, to.Ptr("1.0.*"), "existingParam"))

	// Test with non-existing parameter
	assert.False(t, az.AssignmentReferencedDefinitionHasParameter(resID, to.Ptr("1.0.*"), "nonExistentParam"))

	// Test with non-existing definition (should return true to avoid false positives)
	resID2, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/nonExistent")
	require.NoError(t, err)
	assert.True(t, az.AssignmentReferencedDefinitionHasParameter(resID2, nil, "anyParam"))
}

func TestAddPolicyDefinitionsMultipleVersions(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Add multiple versions of the same policy definition
	pd1 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("1.0.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
		},
	})

	pd2 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("1.1.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
		},
	})

	pd3 := assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr("testPolicy"),
		Properties: &armpolicy.DefinitionProperties{
			Version:    to.Ptr("2.0.0"),
			PolicyType: to.Ptr(armpolicy.PolicyTypeCustom),
			Mode:       to.Ptr("All"),
			PolicyRule: map[string]any{},
		},
	})

	require.NoError(t, az.AddPolicyDefinitions(pd1))
	require.NoError(t, az.AddPolicyDefinitions(pd2))
	require.NoError(t, az.AddPolicyDefinitions(pd3))

	// Verify all versions exist using version constraints
	assert.True(t, az.PolicyDefinitionExists("testPolicy", to.Ptr("1.0.*")))
	assert.True(t, az.PolicyDefinitionExists("testPolicy", to.Ptr("1.1.*")))
	assert.True(t, az.PolicyDefinitionExists("testPolicy", to.Ptr("2.0.*")))

	// Verify there's only one entry in the map
	assert.Len(t, az.PolicyDefinitions(), 1)
}

func TestAddPolicySetDefinitionsMultipleVersions(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Add multiple versions of the same policy set definition
	psd1 := assets.NewPolicySetDefinition(armpolicy.SetDefinition{
		Name: to.Ptr("testPolicySet"),
		Properties: &armpolicy.SetDefinitionProperties{
			Version:           to.Ptr("1.0.0"),
			PolicyType:        to.Ptr(armpolicy.PolicyTypeCustom),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
		},
	})

	psd2 := assets.NewPolicySetDefinition(armpolicy.SetDefinition{
		Name: to.Ptr("testPolicySet"),
		Properties: &armpolicy.SetDefinitionProperties{
			Version:           to.Ptr("1.1.0"),
			PolicyType:        to.Ptr(armpolicy.PolicyTypeCustom),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
		},
	})

	require.NoError(t, az.AddPolicySetDefinitions(psd1))
	require.NoError(t, az.AddPolicySetDefinitions(psd2))

	// Verify all versions exist using version constraints
	assert.True(t, az.PolicySetDefinitionExists("testPolicySet", to.Ptr("1.0.*")))
	assert.True(t, az.PolicySetDefinitionExists("testPolicySet", to.Ptr("1.1.*")))

	// Verify there's only one entry in the map
	assert.Len(t, az.PolicySetDefinitions(), 1)
}

func TestAssignmentReferencedDefinitionHasParameterPolicySet(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create a policy set definition with parameters
	psd := assets.NewPolicySetDefinition(armpolicy.SetDefinition{
		Name: to.Ptr("testPolicySet"),
		Properties: &armpolicy.SetDefinitionProperties{
			Version:           to.Ptr("1.0.0"),
			PolicyType:        to.Ptr(armpolicy.PolicyTypeCustom),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"setParam": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
			},
		},
	})

	require.NoError(t, az.AddPolicySetDefinitions(psd))

	resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/testPolicySet")
	require.NoError(t, err)

	// Test with existing parameter using version constraint
	assert.True(t, az.AssignmentReferencedDefinitionHasParameter(resID, to.Ptr("1.0.*"), "setParam"))

	// Test with non-existing parameter
	assert.False(t, az.AssignmentReferencedDefinitionHasParameter(resID, to.Ptr("1.0.*"), "nonExistentParam"))
}

func TestIntegrationGetDefinitionsFromAzure(t *testing.T) {
	policyDefAzureBackupShouldBeEnabledForVirtualMachines, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/013e242c-8828-4970-87b3-ab247555486d")
	require.NoError(t, err)
	policyDefKubernetesContainerImagesSHouldNotIncludeLatest, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/021f8078-41a0-40e6-81b6-c6597da9f3ee")
	require.NoError(t, err)
	policySetDefAzureCISFoundation, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/1a5bb27d-173f-493e-9568-eb56638dde4d")
	require.NoError(t, err)
	policySetDefAllowUsageCostResources, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/0a2ebd47-3fb9-4735-a006-b7f31ddadd9f")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{
			ResourceID: policyDefAzureBackupShouldBeEnabledForVirtualMachines,
			Version:    to.Ptr("3.0.*"),
		},
		{
			ResourceID: policyDefKubernetesContainerImagesSHouldNotIncludeLatest,
		},
		{
			ResourceID: policySetDefAzureCISFoundation,
			Version:    to.Ptr("16.*.*"),
		},
		{
			ResourceID: policySetDefAzureCISFoundation,
			Version:    to.Ptr("16.*.*"),
		},
		{
			ResourceID: policySetDefAllowUsageCostResources,
		},
	}

	az := NewAlzLib(nil)
	tok, err := auth.NewToken()
	require.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", tok, &arm.ClientOptions{
		ClientOptions: corepolicy.ClientOptions{
			Cloud: auth.GetCloudFromEnv(),
		},
	})
	require.NoError(t, err)
	az.AddPolicyClient(cf)

	ctx := t.Context()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	require.NoError(t, err)
	assert.True(t, az.PolicyDefinitionExists("013e242c-8828-4970-87b3-ab247555486d", to.Ptr("3.0.*")))
	assert.True(t, az.PolicyDefinitionExists("021f8078-41a0-40e6-81b6-c6597da9f3ee", nil))
	assert.True(t, az.PolicySetDefinitionExists("1a5bb27d-173f-493e-9568-eb56638dde4d", to.Ptr("16.*.*")))
	assert.True(t, az.PolicySetDefinitionExists("0a2ebd47-3fb9-4735-a006-b7f31ddadd9f", nil))
}

// mockBuiltInCache implements the BuiltInCache interface for testing.
type mockBuiltInCache struct {
	policyDefs    map[string]*assets.PolicyDefinitionVersions
	policySetDefs map[string]*assets.PolicySetDefinitionVersions
}

func (m *mockBuiltInCache) PolicyDefinitions() map[string]*assets.PolicyDefinitionVersions {
	return m.policyDefs
}

func (m *mockBuiltInCache) PolicySetDefinitions() map[string]*assets.PolicySetDefinitionVersions {
	return m.policySetDefs
}

func (m *mockBuiltInCache) PolicyDefinitionVersionsByName(name string) *assets.PolicyDefinitionVersions {
	return m.policyDefs[name]
}

func (m *mockBuiltInCache) PolicySetDefinitionVersionsByName(name string) *assets.PolicySetDefinitionVersions {
	return m.policySetDefs[name]
}

// TestAddCacheStoresCacheReference verifies that AddCache stores the cache reference for
// lazy lookup, and that definitions are not immediately loaded into AlzLib.
func TestAddCacheStoresCacheReference(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Build a mock cache with one policy definition and one policy set definition.
	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "cached-pd", "1.0.0"), false))

	psdvs := assets.NewPolicySetDefinitionVersions()
	require.NoError(t, psdvs.Add(testPolicySetDefinition(t, "cached-psd", "1.0.0"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"cached-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{"cached-psd": psdvs},
	}

	az.AddCache(cache)

	// Definitions must NOT be loaded eagerly - they are only fetched on demand.
	assert.False(t, az.PolicyDefinitionExists("cached-pd", to.Ptr("1.0.*")),
		"cached-pd should not be eagerly loaded into AlzLib by AddCache")
	assert.False(t, az.PolicySetDefinitionExists("cached-psd", to.Ptr("1.0.*")),
		"cached-psd should not be eagerly loaded into AlzLib by AddCache")
}

// TestAddCacheDefinitionsLoadedOnDemand verifies that definitions are fetched from cache
// during GetDefinitionsFromAzure and are accessible in AlzLib afterwards.
func TestAddCacheDefinitionsLoadedOnDemand(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "cached-pd", "1.0.0"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"cached-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/cached-pd")
	require.NoError(t, err)

	err = az.GetDefinitionsFromAzure(context.Background(), []BuiltInRequest{
		{ResourceID: pdResID, Version: to.Ptr("1.0.*")},
	})
	require.NoError(t, err)

	// After GetDefinitionsFromAzure, the definition should be in AlzLib.
	assert.True(t, az.PolicyDefinitionExists("cached-pd", to.Ptr("1.0.*")))
}

// TestAddCacheExistingDefinitionNotOverwritten verifies that definitions already in AlzLib
// are not replaced by a cache lookup - they are found first in AlzLib and skipped.
func TestAddCacheExistingDefinitionNotOverwritten(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Pre-populate with a specific version.
	existingPd := testPolicyDefinition(t, "existing-pd", "1.0.0")
	require.NoError(t, az.AddPolicyDefinitions(existingPd))

	// Cache has the same version.
	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "existing-pd", "1.0.0"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"existing-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/existing-pd")
	require.NoError(t, err)

	// Requesting a version that already exists in AlzLib should succeed without error.
	err = az.GetDefinitionsFromAzure(context.Background(), []BuiltInRequest{
		{ResourceID: pdResID, Version: to.Ptr("1.0.*")},
	})
	require.NoError(t, err)

	// The pre-existing version 1.0.0 should still be there.
	assert.True(t, az.PolicyDefinitionExists("existing-pd", to.Ptr("1.0.*")))
}

// TestAddCacheDeepCopies verifies that definitions fetched from cache are deep-copied so
// that subsequent mutations to AlzLib do not affect the original cache entries.
func TestAddCacheDeepCopies(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "deep-copy-pd", "1.0.0"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"deep-copy-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/deep-copy-pd")
	require.NoError(t, err)

	// Fetch the definition from cache via GetDefinitionsFromAzure.
	require.NoError(t, az.GetDefinitionsFromAzure(context.Background(), []BuiltInRequest{
		{ResourceID: pdResID, Version: to.Ptr("1.0.*")},
	}))

	// Mutate the definition in AlzLib via SetAssignPermissionsOnDefinitionParameter.
	// This should NOT affect the original cache.
	az.SetAssignPermissionsOnDefinitionParameter("deep-copy-pd", "anyParam")

	// Verify the original cache's definition is unmodified.
	origPd, err := pdvs.GetVersion(to.Ptr("1.0.*"))
	require.NoError(t, err)

	// The original should not have any AssignPermissions set on any parameter.
	if origPd.Properties.Parameters != nil {
		for _, p := range origPd.Properties.Parameters {
			if p.Metadata != nil && p.Metadata.AssignPermissions != nil {
				t.Fatal("cache definition was mutated - deep copy failed")
			}
		}
	}
}

func TestAddCacheEmptyCache(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	assert.Empty(t, az.PolicyDefinitions())
	assert.Empty(t, az.PolicySetDefinitions())
}

// testPolicySetDefinitionWithRefs creates a policy set definition that references sub-policy definitions.
func testPolicySetDefinitionWithRefs(t *testing.T, name, version string, refs []*armpolicy.DefinitionReference) *assets.PolicySetDefinition {
	t.Helper()

	desc := name + " description"

	return &assets.PolicySetDefinition{
		SetDefinition: armpolicy.SetDefinition{
			Name: to.Ptr(name),
			Properties: &armpolicy.SetDefinitionProperties{
				DisplayName:       to.Ptr(name),
				Description:       &desc,
				Metadata:          map[string]any{},
				PolicyDefinitions: refs,
				Parameters:        map[string]*armpolicy.ParameterDefinitionsValue{},
				PolicyType:        to.Ptr(armpolicy.PolicyTypeBuiltIn),
				Version:           to.Ptr(version),
			},
		},
	}
}

// TestCacheCompleteHitAvoidsPolicyClient verifies that when ALL built-in policy definitions
// and policy set definitions (including sub-referenced PDs) are present in the cache,
// GetDefinitionsFromAzure succeeds without a policy client.
func TestCacheCompleteHitAvoidsPolicyClient(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create a cached PD "sub-pd-1" version 1.0.0
	subPdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, subPdvs.Add(testPolicyDefinition(t, "sub-pd-1", "1.0.0"), false))

	// Create a cached PSD "cached-psd" version 2.0.0 that references "sub-pd-1"
	psdvs := assets.NewPolicySetDefinitionVersions()
	psd := testPolicySetDefinitionWithRefs(t, "cached-psd", "2.0.0", []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/sub-pd-1"),
			PolicyDefinitionReferenceID: to.Ptr("sub-pd-1-ref"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
	})
	require.NoError(t, psdvs.Add(psd, false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"sub-pd-1": subPdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{"cached-psd": psdvs},
	}

	az.AddCache(cache)

	// No policy client is set - this is intentional.
	// Build a request for the cached PSD.
	psdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/cached-psd")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{
			ResourceID: psdResID,
			Version:    to.Ptr("2.0.*"),
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when all definitions are in cache")
}

// TestCacheCompleteHitForDirectPolicyDefinition verifies that a directly referenced
// policy definition (not via a PSD) can be resolved from cache without a policy client.
func TestCacheCompleteHitForDirectPolicyDefinition(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "direct-pd", "3.0.0"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"direct-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/direct-pd")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{
			ResourceID: pdResID,
			Version:    to.Ptr("3.0.*"),
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when policy definition is in cache")
}

// TestCacheCompleteHitForVersionlessRequest verifies that a request with no version
// constraint (nil) can be resolved from cache when the cache has versioned entries.
func TestCacheCompleteHitForVersionlessRequest(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "versionless-req-pd", "2.0.0"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"versionless-req-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/versionless-req-pd")
	require.NoError(t, err)

	// Request with nil version (no constraint) - should find the latest in cache.
	reqs := []BuiltInRequest{
		{
			ResourceID: pdResID,
			Version:    nil,
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when requesting versionless and cache has versioned entry")
}

// TestCacheMissingSubReferencedPDFailsWithoutClient verifies that when a PSD is cached
// but one of its sub-referenced policy definitions is NOT in the cache,
// GetDefinitionsFromAzure fails because there is no policy client to fetch the missing PD.
func TestCacheMissingSubReferencedPDFailsWithoutClient(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create a cached PSD that references two PDs, but only cache one of them.
	subPdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, subPdvs.Add(testPolicyDefinition(t, "present-pd", "1.0.0"), false))

	psdvs := assets.NewPolicySetDefinitionVersions()
	psd := testPolicySetDefinitionWithRefs(t, "incomplete-psd", "1.0.0", []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/present-pd"),
			PolicyDefinitionReferenceID: to.Ptr("present-ref"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/missing-pd"),
			PolicyDefinitionReferenceID: to.Ptr("missing-ref"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
	})
	require.NoError(t, psdvs.Add(psd, false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"present-pd": subPdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{"incomplete-psd": psdvs},
	}

	az.AddCache(cache)

	psdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/incomplete-psd")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{
			ResourceID: psdResID,
			Version:    to.Ptr("1.0.*"),
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	require.Error(t, err, "expected error when sub-referenced PD is missing from cache and no policy client")
	assert.Contains(t, err.Error(), "policy client not set")
}

// TestCacheMissingDirectPDFailsWithoutClient verifies that when a directly referenced
// policy definition is NOT in the cache, GetDefinitionsFromAzure fails.
func TestCacheMissingDirectPDFailsWithoutClient(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Empty cache.
	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/not-in-cache")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{
			ResourceID: pdResID,
			Version:    to.Ptr("1.0.*"),
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	require.Error(t, err, "expected error when PD is missing from cache and no policy client")
	assert.Contains(t, err.Error(), "policy client not set")
}

// TestCacheMissingPSDFailsWithoutClient verifies that when a referenced policy set definition
// is NOT in the cache, GetDefinitionsFromAzure fails.
func TestCacheMissingPSDFailsWithoutClient(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	psdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/not-in-cache")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{
			ResourceID: psdResID,
			Version:    to.Ptr("1.0.*"),
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	require.Error(t, err, "expected error when PSD is missing from cache and no policy client")
	assert.Contains(t, err.Error(), "policy client not set")
}

// TestCacheVersionMismatchFailsWithoutClient verifies that when a cached definition exists
// but the requested version constraint doesn't match any cached version,
// GetDefinitionsFromAzure tries to fetch from Azure and fails.
func TestCacheVersionMismatchFailsWithoutClient(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Cache has version 1.0.0, but we request 2.0.*
	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "version-mismatch-pd", "1.0.0"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"version-mismatch-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/version-mismatch-pd")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{
			ResourceID: pdResID,
			Version:    to.Ptr("2.0.*"),
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	require.Error(t, err, "expected error when version constraint doesn't match cached version")
	assert.Contains(t, err.Error(), "policy client not set")
}

// TestCacheMultiplePDVersionsMatchesConstraint verifies that when the cache has multiple
// versions of a PD, the correct version is matched by a constraint.
func TestCacheMultiplePDVersionsMatchesConstraint(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "multi-ver-pd", "1.0.0"), false))
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "multi-ver-pd", "2.0.0"), false))
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "multi-ver-pd", "3.0.0"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"multi-ver-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/multi-ver-pd")
	require.NoError(t, err)

	// Request version 2.0.* - should match 2.0.0 in cache.
	reqs := []BuiltInRequest{
		{
			ResourceID: pdResID,
			Version:    to.Ptr("2.0.*"),
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when constraint matches a cached version")
}

// TestCacheCompleteHitMultiplePSDsAndPDs verifies that multiple PSDs and PDs from cache
// can all be resolved without a policy client.
func TestCacheCompleteHitMultiplePSDsAndPDs(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create sub PDs
	pd1vs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pd1vs.Add(testPolicyDefinition(t, "pd-a", "1.0.0"), false))

	pd2vs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pd2vs.Add(testPolicyDefinition(t, "pd-b", "2.0.0"), false))

	pd3vs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pd3vs.Add(testPolicyDefinition(t, "pd-c", "1.0.0"), false))

	// PSD-1 references pd-a and pd-b
	psd1vs := assets.NewPolicySetDefinitionVersions()
	psd1 := testPolicySetDefinitionWithRefs(t, "psd-1", "1.0.0", []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/pd-a"),
			PolicyDefinitionReferenceID: to.Ptr("ref-a"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/pd-b"),
			PolicyDefinitionReferenceID: to.Ptr("ref-b"),
			DefinitionVersion:           to.Ptr("2.0.*"),
		},
	})
	require.NoError(t, psd1vs.Add(psd1, false))

	// PSD-2 references pd-c
	psd2vs := assets.NewPolicySetDefinitionVersions()
	psd2 := testPolicySetDefinitionWithRefs(t, "psd-2", "1.0.0", []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/pd-c"),
			PolicyDefinitionReferenceID: to.Ptr("ref-c"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
	})
	require.NoError(t, psd2vs.Add(psd2, false))

	cache := &mockBuiltInCache{
		policyDefs: map[string]*assets.PolicyDefinitionVersions{
			"pd-a": pd1vs,
			"pd-b": pd2vs,
			"pd-c": pd3vs,
		},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{
			"psd-1": psd1vs,
			"psd-2": psd2vs,
		},
	}

	az.AddCache(cache)

	psd1ResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/psd-1")
	require.NoError(t, err)
	psd2ResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/psd-2")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{ResourceID: psd1ResID, Version: to.Ptr("1.0.*")},
		{ResourceID: psd2ResID, Version: to.Ptr("1.0.*")},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when all PSDs and their sub-PDs are in cache")
}

// TestCachePSDWithNilDefinitionVersionRefs verifies that when a cached PSD references
// sub-PDs without a DefinitionVersion (nil), the cache resolves them correctly.
func TestCachePSDWithNilDefinitionVersionRefs(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "no-ver-ref-pd", "1.0.0"), false))

	psdvs := assets.NewPolicySetDefinitionVersions()
	psd := testPolicySetDefinitionWithRefs(t, "psd-nil-ver-refs", "1.0.0", []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/no-ver-ref-pd"),
			PolicyDefinitionReferenceID: to.Ptr("ref-no-ver"),
			DefinitionVersion:           nil, // no version constraint
		},
	})
	require.NoError(t, psdvs.Add(psd, false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"no-ver-ref-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{"psd-nil-ver-refs": psdvs},
	}

	az.AddCache(cache)

	psdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/psd-nil-ver-refs")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{ResourceID: psdResID, Version: to.Ptr("1.0.*")},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when PSD references sub-PDs without version constraint and PDs are cached")
}

// TestCachePreviewVersionConstraintMatch verifies that preview version constraints
// (e.g., "1.*.*-preview") are correctly matched against cached preview versions.
func TestCachePreviewVersionConstraintMatch(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(testPolicyDefinition(t, "preview-pd", "1.0.0-preview"), false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"preview-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/preview-pd")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{
			ResourceID: pdResID,
			Version:    to.Ptr("1.*.*-preview"),
		},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when preview version constraint matches cached preview version")
}

// TestCacheMixedDirectAndPSDRequests verifies that a mix of direct PD requests and
// PSD requests (with sub-referenced PDs) can all be resolved from cache.
func TestCacheMixedDirectAndPSDRequests(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Direct PD
	directPdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, directPdvs.Add(testPolicyDefinition(t, "direct-only-pd", "2.0.0"), false))

	// Sub PD referenced by PSD
	subPdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, subPdvs.Add(testPolicyDefinition(t, "sub-only-pd", "1.0.0"), false))

	psdvs := assets.NewPolicySetDefinitionVersions()
	psd := testPolicySetDefinitionWithRefs(t, "mixed-psd", "1.0.0", []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/sub-only-pd"),
			PolicyDefinitionReferenceID: to.Ptr("sub-ref"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
	})
	require.NoError(t, psdvs.Add(psd, false))

	cache := &mockBuiltInCache{
		policyDefs: map[string]*assets.PolicyDefinitionVersions{
			"direct-only-pd": directPdvs,
			"sub-only-pd":    subPdvs,
		},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{"mixed-psd": psdvs},
	}

	az.AddCache(cache)

	directResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/direct-only-pd")
	require.NoError(t, err)
	psdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/mixed-psd")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{ResourceID: directResID, Version: to.Ptr("2.0.*")},
		{ResourceID: psdResID, Version: to.Ptr("1.0.*")},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when both direct PDs and PSD sub-refs are in cache")
}

// TestCacheVersionlessDefinitionInCache verifies that versionless definitions
// (no Properties.Version set) in the cache can be resolved for requests with nil version.
func TestCacheVersionlessDefinitionInCache(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create a versionless PD (Version is nil).
	versionlessPd := &assets.PolicyDefinition{
		Definition: armpolicy.Definition{
			Name: to.Ptr("versionless-pd"),
			Properties: &armpolicy.DefinitionProperties{
				DisplayName: to.Ptr("versionless-pd"),
				Description: to.Ptr("versionless description"),
				Metadata:    map[string]any{},
				PolicyRule:  map[string]any{"if": map[string]any{}, "then": map[string]any{}},
				Version:     nil,
			},
		},
	}

	pdvs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pdvs.Add(versionlessPd, false))

	cache := &mockBuiltInCache{
		policyDefs:    map[string]*assets.PolicyDefinitionVersions{"versionless-pd": pdvs},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{},
	}

	az.AddCache(cache)

	pdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/versionless-pd")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{ResourceID: pdResID, Version: nil},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	assert.NoError(t, err, "expected no error when versionless definition is in cache and request has nil version")
}

// TestCachePartialPSDMissOneSubPDOutOfMany verifies that even if only one sub-referenced PD
// is missing from cache (out of many), GetDefinitionsFromAzure fails.
func TestCachePartialPSDMissOneSubPDOutOfMany(t *testing.T) {
	t.Parallel()

	az := NewAlzLib(nil)

	// Create 3 sub PDs but only cache 2 of them
	pd1vs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pd1vs.Add(testPolicyDefinition(t, "cached-sub-1", "1.0.0"), false))

	pd2vs := assets.NewPolicyDefinitionVersions()
	require.NoError(t, pd2vs.Add(testPolicyDefinition(t, "cached-sub-2", "1.0.0"), false))

	// pd3 ("missing-sub-3") is NOT added to cache

	psdvs := assets.NewPolicySetDefinitionVersions()
	psd := testPolicySetDefinitionWithRefs(t, "partial-psd", "1.0.0", []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/cached-sub-1"),
			PolicyDefinitionReferenceID: to.Ptr("ref-1"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/cached-sub-2"),
			PolicyDefinitionReferenceID: to.Ptr("ref-2"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
		{
			PolicyDefinitionID:          to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/missing-sub-3"),
			PolicyDefinitionReferenceID: to.Ptr("ref-3"),
			DefinitionVersion:           to.Ptr("1.0.*"),
		},
	})
	require.NoError(t, psdvs.Add(psd, false))

	cache := &mockBuiltInCache{
		policyDefs: map[string]*assets.PolicyDefinitionVersions{
			"cached-sub-1": pd1vs,
			"cached-sub-2": pd2vs,
		},
		policySetDefs: map[string]*assets.PolicySetDefinitionVersions{"partial-psd": psdvs},
	}

	az.AddCache(cache)

	psdResID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/partial-psd")
	require.NoError(t, err)

	reqs := []BuiltInRequest{
		{ResourceID: psdResID, Version: to.Ptr("1.0.*")},
	}

	ctx := context.Background()
	err = az.GetDefinitionsFromAzure(ctx, reqs)
	require.Error(t, err, "expected error when one sub-referenced PD is missing from cache")
	assert.Contains(t, err.Error(), "policy client not set")
}

func testPolicyDefinition(t *testing.T, name, version string) *assets.PolicyDefinition {
	t.Helper()

	desc := name + " description"

	return &assets.PolicyDefinition{
		Definition: armpolicy.Definition{
			Name: to.Ptr(name),
			Properties: &armpolicy.DefinitionProperties{
				DisplayName: to.Ptr(name),
				Description: &desc,
				Metadata:    map[string]any{},
				PolicyRule:  map[string]any{"if": map[string]any{}, "then": map[string]any{}},
				Version:     to.Ptr(version),
			},
		},
	}
}

func testPolicySetDefinition(t *testing.T, name, version string) *assets.PolicySetDefinition {
	t.Helper()

	desc := name + " description"

	return &assets.PolicySetDefinition{
		SetDefinition: armpolicy.SetDefinition{
			Name: to.Ptr(name),
			Properties: &armpolicy.SetDefinitionProperties{
				DisplayName:       to.Ptr(name),
				Description:       &desc,
				Metadata:          map[string]any{},
				PolicyDefinitions: []*armpolicy.DefinitionReference{},
				Parameters:        map[string]*armpolicy.ParameterDefinitionsValue{},
				PolicyType:        to.Ptr(armpolicy.PolicyTypeCustom),
				Version:           to.Ptr(version),
			},
		},
	}
}
