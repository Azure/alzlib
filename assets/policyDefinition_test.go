// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func TestNormalizedRoleDefinitionResourceIds(t *testing.T) {
	pd := &PolicyDefinition{
		Definition: armpolicy.Definition{
			Properties: &armpolicy.DefinitionProperties{
				PolicyRule: map[string]any{
					"Then": map[string]any{
						"Details": map[string]any{
							"RoleDefinitionIds": []string{
								"/providers/Microsoft.Authorization/roleDefinitions/role1",
								"/providers/Microsoft.Authorization/roleDefinitions/role2",
							},
						},
					},
				},
			},
		},
	}

	expected := []string{
		"/providers/Microsoft.Authorization/roleDefinitions/role1",
		"/providers/Microsoft.Authorization/roleDefinitions/role2",
	}

	ids, err := pd.NormalizedRoleDefinitionResourceIds()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ids) != len(expected) {
		t.Fatalf("expected %d role definition ids, got %d", len(expected), len(ids))
	}

	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("expected role definition id %s, got %s", expected[i], id)
		}
	}
}
