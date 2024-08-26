// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"errors"

	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

var CheckResourceTypeIsCorrect = checker.NewValidatorCheck("Resource type is correct", checkResourceTypeIsCorrect)

func checkResourceTypeIsCorrect(anyType any) error {
	switch anyType := anyType.(type) {
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
