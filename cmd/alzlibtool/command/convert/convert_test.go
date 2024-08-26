package convert

import (
	"bytes"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func TestLibraryFileName(t *testing.T) {
	definition := &armpolicy.Definition{
		Name: to.Ptr("policy1"),
	}
	expected := "policy1.alz_policy_definition.json"
	result := libraryFileName(definition)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

	setDefinition := &armpolicy.SetDefinition{
		Name: to.Ptr("policySet1"),
	}
	expected = "policySet1.alz_policy_set_definition.json"
	result = libraryFileName(setDefinition)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

	other := "other"
	expected = ""
	result = libraryFileName(other)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

func TestRemoveArmFunctionEscaping(t *testing.T) {
	input := []byte(`"[[someFunction()]"`)
	expected := []byte(`"[someFunction()]"`)
	result := removeArmFunctionEscaping(input)
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}
