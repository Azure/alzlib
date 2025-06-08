// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"errors"
	"fmt"

	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func CheckResourceTypeIsCorrect(inputs ...any) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"Resource type is correct",
		func() error {
			if len(inputs) != 1 {
				return fmt.Errorf("checkResourceTypeIsCorrect: expected 1 input, got %d", len(inputs))
			}
			return checkResourceTypeIsCorrect(inputs[0])
		},
	)
}

func checkResourceTypeIsCorrect(input any) error {
	switch anyType := input.(type) {
	case *armpolicy.Definition:
		if anyType.Type == nil || *anyType.Type != "Microsoft.Authorization/policyDefinitions" {
			return errors.New("resource is not a policy definition")
		}
	case *armpolicy.SetDefinition:
		if anyType.Type == nil || *anyType.Type != "Microsoft.Authorization/policySetDefinitions" {
			return errors.New("resource is not a policy set definition")
		}
	}
	return nil
}
