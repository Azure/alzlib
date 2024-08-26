package assets

import "testing"

func TestNameFromResourceId(t *testing.T) {
	resId := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM"
	expectedName := "myVM"

	name, err := NameFromResourceId(resId)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if name != expectedName {
		t.Fatalf("got %s, want %s", name, expectedName)
	}
}

func TestResourceTypeFromResourceId(t *testing.T) {
	resId := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM"
	expectedType := "virtualMachines"
	resourceType, err := ResourceTypeFromResourceId(resId)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resourceType != expectedType {
		t.Fatalf("got %s, want %s", resourceType, expectedType)
	}
}
