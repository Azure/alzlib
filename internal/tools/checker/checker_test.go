// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checker_test

import (
	"testing"

	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/internal/tools/checks"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func TestValidator_Validate(t *testing.T) {
	// Test case 1: Valid resource
	validResource := &armpolicy.Definition{
		Type: to.Ptr("Microsoft.Authorization/policyDefinitions"),
	}

	validCheck := checks.CheckResourceTypeIsCorrect(validResource)
	validator := checker.NewValidator(validCheck)

	err := validator.Validate()
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	// Test case 2: Invalid resource
	invalidResource := &armpolicy.Definition{
		Type: to.Ptr("InvalidType"),
	}
	invalidCheck := checks.CheckResourceTypeIsCorrect(invalidResource)
	validator = checker.NewValidator(invalidCheck)
	err = validator.Validate()
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}
