// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"context"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The following fixtures reproduce the shape of the official Azure built-in Windows AMA/DCR
// initiative `9575b8b7-78ab-4281-b53b-d3c1ace2260b`, which passes `DcrResourceId` to the policy
// definition `eab1f514-22e3-42e3-9a1f-e1dc9199355c` that declares `dcrResourceId`.
// See https://github.com/Azure/Azure-Landing-Zones/issues/4248.
const (
	dcrMemberDefinitionName = "eab1f514-22e3-42e3-9a1f-e1dc9199355c"
	dcrInitiativeName       = "9575b8b7-78ab-4281-b53b-d3c1ace2260b"
	dcrAssignmentName       = "Deploy-VM-Monitoring"
	dcrMemberParameterName  = "dcrResourceId"
	dcrInitiativeParamName  = "DcrResourceId"
	dcrRoleDefinitionID     = "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
	dcrResourceID           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ama/" +
		"providers/Microsoft.Insights/dataCollectionRules/dcr-windows"
)

// newDcrMemberDefinition returns a policy definition declaring memberParamName with
// assignPermissions set to true.
func newDcrMemberDefinition(memberParamName string) *assets.PolicyDefinition {
	return assets.NewPolicyDefinition(armpolicy.Definition{
		Name: to.Ptr(dcrMemberDefinitionName),
		Type: to.Ptr("Microsoft.Authorization/policyDefinitions"),
		Properties: &armpolicy.DefinitionProperties{
			PolicyRule: map[string]any{
				"then": map[string]any{
					"details": map[string]any{
						"roleDefinitionIds": []any{dcrRoleDefinitionID},
					},
				},
			},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				memberParamName: {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(true),
					},
				},
			},
		},
	})
}

// newDcrInitiative returns an initiative that passes refParamName to the member definition.
func newDcrInitiative(refParamName string) *assets.PolicySetDefinition {
	return assets.NewPolicySetDefinition(armpolicy.SetDefinition{
		Name: to.Ptr(dcrInitiativeName),
		Type: to.Ptr("Microsoft.Authorization/policySetDefinitions"),
		Properties: &armpolicy.SetDefinitionProperties{
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				dcrInitiativeParamName: {Type: to.Ptr(armpolicy.ParameterTypeString)},
			},
			PolicyDefinitions: []*armpolicy.DefinitionReference{
				{
					PolicyDefinitionReferenceID: to.Ptr("WindowsDcrAssociation"),
					PolicyDefinitionID: to.Ptr(
						"/providers/Microsoft.Authorization/policyDefinitions/" + dcrMemberDefinitionName,
					),
					Parameters: map[string]*armpolicy.ParameterValuesValue{
						refParamName: {Value: "[parameters('" + dcrInitiativeParamName + "')]"},
					},
				},
			},
		},
	})
}

// newDcrAssignment returns an assignment of the initiative supplying assignmentParamName.
func newDcrAssignment(assignmentParamName string) *assets.PolicyAssignment {
	return assets.NewPolicyAssignment(armpolicy.Assignment{
		Name:     to.Ptr(dcrAssignmentName),
		Type:     to.Ptr("Microsoft.Authorization/policyAssignments"),
		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr(
				"/providers/Microsoft.Authorization/policySetDefinitions/" + dcrInitiativeName,
			),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				assignmentParamName: {Value: dcrResourceID},
			},
		},
	})
}

// newDcrArchetype returns an archetype referencing the initiative assignment.
func newDcrArchetype() *alzlib.Archetype {
	arch := alzlib.NewArchetype("dcr")
	arch.PolicyAssignments.Add(dcrAssignmentName)

	return arch
}

func newDcrManagementGroupAddRequest() managementGroupAddRequest {
	return managementGroupAddRequest{
		id:               "mg1",
		displayName:      "mg1",
		parentID:         "external",
		parentIsExternal: true,
		archetypes:       []*alzlib.Archetype{newDcrArchetype()},
		location:         eastUSLocation,
	}
}

// TestAddManagementGroupParameterNameCasing asserts that the hierarchy accepts an initiative that
// passes a case-only variant of a member definition parameter name, as Azure does, while a
// genuinely missing parameter still fails.
func TestAddManagementGroupParameterNameCasing(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		name            string
		memberParamName string
		refParamName    string
		errContains     string
	}{
		{
			name:            "exact match",
			memberParamName: dcrMemberParameterName,
			refParamName:    dcrMemberParameterName,
		},
		{
			name:            "case only difference",
			memberParamName: dcrMemberParameterName,
			refParamName:    dcrInitiativeParamName,
		},
		{
			name:            "genuinely missing parameter",
			memberParamName: "minPort",
			refParamName:    dcrInitiativeParamName,
			errContains:     "does not match a parameter in referenced definition",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az := alzlib.NewAlzLib(nil)
			require.NoError(t, az.AddPolicyDefinitions(newDcrMemberDefinition(tc.memberParamName)))
			require.NoError(t, az.AddPolicySetDefinitions(newDcrInitiative(tc.refParamName)))
			require.NoError(t, az.AddPolicyAssignments(newDcrAssignment(dcrInitiativeParamName)))

			h := NewHierarchy(az)

			mg, err := h.addManagementGroup(context.Background(), newDcrManagementGroupAddRequest())
			if tc.errContains != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.errContains)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, mg)
			assert.Contains(t, mg.policyAssignments, dcrAssignmentName)
		})
	}
}

// TestAddManagementGroupAmbiguousParameterName asserts that a parameter name matching more than one
// member definition parameter case-insensitively is rejected deterministically.
func TestAddManagementGroupAmbiguousParameterName(t *testing.T) {
	t.Parallel()

	pd := newDcrMemberDefinition(dcrMemberParameterName)
	pd.Properties.Parameters["DCRRESOURCEID"] = &armpolicy.ParameterDefinitionsValue{
		Type: to.Ptr(armpolicy.ParameterTypeString),
	}

	az := alzlib.NewAlzLib(nil)
	require.NoError(t, az.AddPolicyDefinitions(pd))
	require.NoError(t, az.AddPolicySetDefinitions(newDcrInitiative(dcrInitiativeParamName)))
	require.NoError(t, az.AddPolicyAssignments(newDcrAssignment(dcrInitiativeParamName)))

	h := NewHierarchy(az)

	mg, err := h.addManagementGroup(context.Background(), newDcrManagementGroupAddRequest())
	require.Error(t, err)
	assert.Nil(t, mg)
	assert.ErrorContains(t, err, "is ambiguous")
}

// TestWithParametersDoesNotDuplicateCaseVariantKeys asserts that supplying a case-only variant of a
// parameter the assignment already sets overwrites it, rather than emitting two parameters that
// Azure would treat as duplicates.
func TestWithParametersDoesNotDuplicateCaseVariantKeys(t *testing.T) {
	t.Parallel()

	az := alzlib.NewAlzLib(nil)
	require.NoError(t, az.AddPolicyDefinitions(newDcrMemberDefinition(dcrMemberParameterName)))
	require.NoError(t, az.AddPolicySetDefinitions(newDcrInitiative(dcrMemberParameterName)))

	pa := newDcrAssignment(dcrInitiativeParamName)
	require.NoError(t, az.AddPolicyAssignments(pa))

	h := NewHierarchy(az)
	mg := &HierarchyManagementGroup{
		id:                "mg1",
		hierarchy:         h,
		policyAssignments: map[string]*assets.PolicyAssignment{*pa.Name: pa},
	}
	h.mgs["mg1"] = mg

	const overriddenID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ama/" +
		"providers/Microsoft.Insights/dataCollectionRules/dcr-other"

	require.NoError(t, mg.ModifyPolicyAssignment(*pa.Name, WithParameters(
		map[string]*armpolicy.ParameterValuesValue{"dcrresourceid": {Value: overriddenID}},
	)))

	assert.Len(t, pa.Properties.Parameters, 1)
	require.Contains(t, pa.Properties.Parameters, dcrInitiativeParamName)
	assert.Equal(t, overriddenID, pa.Properties.Parameters[dcrInitiativeParamName].Value)
}

// TestPolicyRoleAssignmentsParameterNameCasing asserts that the additional role assignment for the
// assignPermissions parameter is still scoped to the supplied data collection rule when the
// initiative and the member definition disagree on parameter name casing.
func TestPolicyRoleAssignmentsParameterNameCasing(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		name                string
		refParamName        string
		assignmentParamName string
	}{
		{
			name:                "exact match",
			refParamName:        dcrMemberParameterName,
			assignmentParamName: dcrInitiativeParamName,
		},
		{
			name:                "reference key differs in case",
			refParamName:        dcrInitiativeParamName,
			assignmentParamName: dcrInitiativeParamName,
		},
		{
			name:                "assignment key differs in case",
			refParamName:        dcrInitiativeParamName,
			assignmentParamName: "dcrresourceid",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az := alzlib.NewAlzLib(nil)
			require.NoError(t, az.AddPolicyDefinitions(newDcrMemberDefinition(dcrMemberParameterName)))
			require.NoError(t, az.AddPolicySetDefinitions(newDcrInitiative(tc.refParamName)))

			pa := newDcrAssignment(tc.assignmentParamName)
			require.NoError(t, az.AddPolicyAssignments(pa))

			h := NewHierarchy(az)
			h.mgs["mg1"] = &HierarchyManagementGroup{
				id:                    "mg1",
				hierarchy:             h,
				policyRoleAssignments: mapset.NewThreadUnsafeSet[PolicyRoleAssignment](),
				policyDefinitions:     make(map[string]*assets.PolicyDefinition),
				policySetDefinitions:  make(map[string]*assets.PolicySetDefinition),
				policyAssignments:     map[string]*assets.PolicyAssignment{*pa.Name: pa},
			}

			res, err := h.PolicyRoleAssignments(context.Background())
			require.NoError(t, err)

			assert.True(t, res.Contains(PolicyRoleAssignment{
				AssignmentName:    dcrAssignmentName,
				RoleDefinitionID:  dcrRoleDefinitionID,
				Scope:             dcrResourceID,
				ManagementGroupID: "mg1",
			}), "expected a role assignment scoped to the supplied data collection rule, got %v", res.ToSlice())
		})
	}
}
