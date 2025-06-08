// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

func CheckDefaults(inputs ...any) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"CheckDefaults: invalid number of inputs",
		func() error {
			if len(inputs) != 1 {
				return fmt.Errorf("checkDefaults: expected 1 input, got %d", len(inputs))
			}
			return checkDefaults(inputs[0])
		},
	)
}

func checkDefaults(input any) error {
	az, ok := input.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkDefaults: expected *alzlib.AlzLib, got %T", input)
	}
	defs := az.PolicyDefaultValues()
	for _, def := range defs {
		pdv := az.PolicyDefaultValue(def)
		for _, assignment := range pdv.Assignments() {
			a := az.PolicyAssignment(assignment)
			if a == nil {
				return fmt.Errorf("checkDefaults: policy assignment `%s`, referenced by default `%s` is not found in the library", assignment, def)
			}
			// We need to check that the referenced definition has the parameter as it may not be present in the assignment (e.g. if it has a default value)
			// First let's get the referenced policy definition id and parse it into a resource id type.
			var pdIdStr string
			if a.Properties.PolicyDefinitionID == nil {
				return fmt.Errorf("checkDefaults: policy assignment `%s`, referenced by default `%s` does not have a policy definition ID", assignment, def)
			}
			pdIdStr = *a.Properties.PolicyDefinitionID
			pdResId, err := arm.ParseResourceID(pdIdStr)
			if err != nil {
				return fmt.Errorf("checkDefaults: policy assignment `%s`, referenced by default `%s` has an invalid policy definition ID", assignment, def)
			}
			// Now we can check that the parameters are present in the referenced definition
			for _, param := range pdv.AssignmentParameters(assignment) {
				if !az.AssignmentReferencedDefinitionHasParameter(pdResId, param) {
					return fmt.Errorf("checkDefaults: policy assignment `%s`, referenced by default `%s` has a parameter `%s` that is not present in the referenced definition", assignment, def, param)
				}
			}
		}
	}
	return nil
}
