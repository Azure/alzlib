// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

// CheckDefaults is a validator check that ensures all policy default values are valid.
var CheckDefaults = checker.NewValidatorCheck("All defaults are valid", checkDefaults)

func checkDefaults(azany any) error {
	az, ok := azany.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkDefaults: expected *alzlib.AlzLib, got %T", azany)
	}

	defs := az.PolicyDefaultValues()
	for _, def := range defs {
		pdv := az.PolicyDefaultValue(def)
		for _, assignment := range pdv.Assignments() {
			a := az.PolicyAssignment(assignment)
			if a == nil {
				return fmt.Errorf(
					"checkDefaults: policy assignment `%s`, referenced by default `%s` is not found in the library",
					assignment,
					def,
				)
			}
			// We need to check that the referenced definition has the parameter as it may not be present
			// in the assignment
			// (e.g. if it has a default value)
			// First let's get the referenced policy definition id and parse it into a resource id type.
			var pdIDStr string

			if a.Properties.PolicyDefinitionID == nil {
				return fmt.Errorf(
					"checkDefaults: policy assignment `%s`, referenced by default `%s` does not have a policy definition ID",
					assignment,
					def,
				)
			}

			pdIDStr = *a.Properties.PolicyDefinitionID

			pdResID, err := arm.ParseResourceID(pdIDStr)
			if err != nil {
				return fmt.Errorf(
					"checkDefaults: policy assignment `%s`, referenced by default `%s` has an invalid policy definition ID",
					assignment,
					def,
				)
			}
			// Now we can check that the parameters are present in the referenced definition
			for _, param := range pdv.AssignmentParameters(assignment) {
				if !az.AssignmentReferencedDefinitionHasParameter(pdResID, param) {
					return fmt.Errorf(
						"checkDefaults: policy assignment `%s`, referenced by default `%s` has a parameter `%s` "+
							"that is not present in the referenced definition",
						assignment,
						def,
						param,
					)
				}
			}
		}
	}

	return nil
}
