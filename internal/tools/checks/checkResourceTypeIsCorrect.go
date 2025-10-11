// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"errors"
	"fmt"

	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// CheckResourceTypeIsCorrect is a validator check that ensures the resource type is correct for
// policy definitions and set definitions.
func CheckResourceTypeIsCorrect(resourceType any) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"Resource type is correct",
		checkResourceTypeIsCorrect(resourceType),
	)
}

// ErrResourceTypeIsIncorrect is returned when the resource type is incorrect.
var ErrResourceTypeIsIncorrect = errors.New("resource type is incorrect")

// NewErrResourceTypeIsIncorrect creates a new error indicating that the resource type is incorrect.
func NewErrResourceTypeIsIncorrect(resourceType string) error {
	return fmt.Errorf("%w: %s", ErrResourceTypeIsIncorrect, resourceType)
}

func checkResourceTypeIsCorrect(anyType any) func() error {
	return func() error {
		switch anyType := anyType.(type) {
		case *armpolicy.Definition:
			if anyType.Type == nil || *anyType.Type != "Microsoft.Authorization/policyDefinitions" {
				return NewErrResourceTypeIsIncorrect("policy definition")
			}
		case *armpolicy.SetDefinition:
			if anyType.Type == nil || *anyType.Type != "Microsoft.Authorization/policySetDefinitions" {
				return NewErrResourceTypeIsIncorrect("policy set definition")
			}
		}

		return nil
	}
}
