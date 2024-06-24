package assets

import (
	"reflect"
	"testing"

	"github.com/Azure/alzlib/to"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func TestGetReferencedPolicyDefinitionNames(t *testing.T) {
	psd := NewPolicySetDefinition(armpolicy.SetDefinition{
		Properties: &armpolicy.SetDefinitionProperties{
			PolicyDefinitions: []*armpolicy.DefinitionReference{
				{
					PolicyDefinitionID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Authorization/policyDefinitions/policy1"),
				},
				{
					PolicyDefinitionID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Authorization/policyDefinitions/policy2"),
				},
			},
		},
	})

	expectedNames := []string{"policy1", "policy2"}
	names, err := psd.ReferencedPolicyDefinitionNames()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(names, expectedNames) {
		t.Fatalf("got %v, want %v", names, expectedNames)
	}
}

func TestGetPolicyDefinitionReferences(t *testing.T) {
	psd := NewPolicySetDefinition(armpolicy.SetDefinition{
		Properties: &armpolicy.SetDefinitionProperties{
			PolicyDefinitions: []*armpolicy.DefinitionReference{
				{
					PolicyDefinitionID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Authorization/policyDefinitions/policy1"),
				},
				{
					PolicyDefinitionID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Authorization/policyDefinitions/policy2"),
				},
			},
		},
	})
	expectedReferences := []*armpolicy.DefinitionReference{
		{
			PolicyDefinitionID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Authorization/policyDefinitions/policy1"),
		},
		{
			PolicyDefinitionID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Authorization/policyDefinitions/policy2"),
		},
	}
	references, err := psd.PolicyDefinitionReferences()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(references, expectedReferences) {
		t.Fatalf("got %v, want %v", references, expectedReferences)
	}
}
