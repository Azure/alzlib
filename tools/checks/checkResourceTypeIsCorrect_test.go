package checks

import (
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func TestCheckResourceType(t *testing.T) {
	definition := &armpolicy.Definition{
		Type: to.Ptr("Microsoft.Authorization/policyDefinitions"),
	}
	err := CheckResourceTypeIsCorrect(definition)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	setDefinition := &armpolicy.SetDefinition{
		Type: to.Ptr("Microsoft.Authorization/policySetDefinitions"),
	}
	err = CheckResourceTypeIsCorrect(setDefinition)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	invalidDefinition := &armpolicy.Definition{
		Type: to.Ptr("InvalidType"),
	}
	err = CheckResourceTypeIsCorrect(invalidDefinition)
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}

	invalidSetDefinition := &armpolicy.SetDefinition{
		Type: to.Ptr("InvalidType"),
	}
	err = CheckResourceTypeIsCorrect(invalidSetDefinition)
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}
