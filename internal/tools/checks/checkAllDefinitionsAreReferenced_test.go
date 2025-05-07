// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"reflect"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
)

func TestCheckAllDefinitionsAreReferenced(t *testing.T) {
	az := alzlib.NewAlzLib(nil)

	az.AddPolicyDefinitions( // nolint: errcheck
		&assets.PolicyDefinition{
			Definition: armpolicy.Definition{
				Name: to.Ptr("policy1"),
			},
		},
		&assets.PolicyDefinition{
			Definition: armpolicy.Definition{
				Name: to.Ptr("policy2"),
			},
		},
	)
	az.AddPolicySetDefinitions( // nolint: errcheck
		&assets.PolicySetDefinition{
			SetDefinition: armpolicy.SetDefinition{
				Name: to.Ptr("policySet1"),
			},
		},
		&assets.PolicySetDefinition{
			SetDefinition: armpolicy.SetDefinition{
				Name: to.Ptr("policySet2"),
			},
		},
	)
	az.AddRoleDefinitions( // nolint: errcheck
		&assets.RoleDefinition{
			RoleDefinition: armauthorization.RoleDefinition{
				Name: to.Ptr("role1"),
			},
		},
		&assets.RoleDefinition{
			RoleDefinition: armauthorization.RoleDefinition{
				Name: to.Ptr("role2"),
			},
		},
	)

	// use reflection/unsafe to populate archetypes
	archetypesNotSettable := reflect.ValueOf(az).Elem().FieldByName("archetypes")
	archetypesPtr := reflect.NewAt(archetypesNotSettable.Type(), (archetypesNotSettable.Addr().UnsafePointer())).Elem()
	archetypes := archetypesPtr.Interface().(map[string]*alzlib.Archetype) //nolint:forcetypeassert

	archetypes["archetype1"] = &alzlib.Archetype{
		PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy1"),
		PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet1"),
		RoleDefinitions:      mapset.NewThreadUnsafeSet("role1"),
		PolicyAssignments:    mapset.NewThreadUnsafeSet[string](),
	}
	archetypes["archetype2"] = &alzlib.Archetype{
		PolicyDefinitions:    mapset.NewThreadUnsafeSet("policy2"),
		PolicySetDefinitions: mapset.NewThreadUnsafeSet("policySet2"),
		RoleDefinitions:      mapset.NewThreadUnsafeSet("role2"),
		PolicyAssignments:    mapset.NewThreadUnsafeSet[string](),
	}

	err := checkAllDefinitionsAreReferenced(az)
	assert.NoError(t, err)

	// Test case with unreferenced definitions
	az.AddPolicyDefinitions( // nolint: errcheck
		&assets.PolicyDefinition{
			Definition: armpolicy.Definition{
				Name: to.Ptr("policy3"),
			},
		},
	)
	az.AddPolicySetDefinitions( // nolint: errcheck
		&assets.PolicySetDefinition{
			SetDefinition: armpolicy.SetDefinition{
				Name: to.Ptr("policySet3"),
			},
		},
	)
	az.AddRoleDefinitions( // nolint: errcheck
		&assets.RoleDefinition{
			RoleDefinition: armauthorization.RoleDefinition{
				Name: to.Ptr("role3"),
			},
		},
	)

	err = checkAllDefinitionsAreReferenced(az)
	assert.ErrorContains(t, err, "found unreferenced definitions [policyDefinitions] [policySetDefinitions] [roleDefinitions]: [policy3], [policySet3], [role3]")
}
