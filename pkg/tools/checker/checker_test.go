package checker_test

import (
	"testing"

	"github.com/Azure/alzlib/pkg/to"
	"github.com/Azure/alzlib/pkg/tools/checker"
	"github.com/Azure/alzlib/pkg/tools/checks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func TestValidator_Validate(t *testing.T) {
	validator := checker.NewValidator(checks.CheckResourceTypeIsCorrect)

	// Test case 1: Valid resource
	validResource := &armpolicy.Definition{
		Type: to.Ptr("Microsoft.Authorization/policyDefinitions"),
	}
	err := validator.Validate(validResource)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	// Test case 2: Invalid resource
	invalidResource := &armpolicy.Definition{
		Type: to.Ptr("InvalidType"),
	}
	err = validator.Validate(invalidResource)
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}
