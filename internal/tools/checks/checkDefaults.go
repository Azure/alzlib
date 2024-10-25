// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/tools/checker"
)

var CheckDefaults = checker.NewValidatorCheck("All defaults are valid", checkDefaults)

func checkDefaults(azany any) error {
	az, ok := azany.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: expected *alzlib.AlzLib, got %T", azany)
	}
	defs := az.PolicyDefaultValues()
	for _, def := range defs {
		pdv := az.PolicyDefaultValue(def)
		for _, assignment := range pdv.Assignments() {
			a := az.PolicyAssignment(assignment)
			if a == nil {
				return fmt.Errorf("checkDefaults: policy assignment `%s`, referenced by default `%s` is not found in the library", assignment, def)
			}
			paramNames := pdv.AssignmentParameters(assignment)
			for _, paramName := range paramNames {
				if _, ok := a.Properties.Parameters[paramName]; !ok {
					return fmt.Errorf("checkDefaults: parameter `%s` in assignment `%s`, referenced by default `%s` is not found in the library", paramName, assignment, def)
				}
			}
		}
	}
	return nil
}
