// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"context"
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/internal/tools/errcheck"
)

func CheckAllArchitectures(inputs ...any) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"All architectures can be deployed",
		func() error {
			if len(inputs) != 1 {
				return fmt.Errorf("checkAllArchitectures: expected 1 input, got %d", len(inputs))
			}
			return checkAllArchitectures(inputs[0])
		},
	)
}

func checkAllArchitectures(input any) error {
	az, ok := input.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: expected *alzlib.AlzLib, got %T", input)
	}
	archs := az.Architectures()
	errs := errcheck.NewCheckerError()
	externalParent := "00000000-0000-0000-0000-000000000000"
	ctx := context.Background()
	for _, v := range archs {
		d := deployment.NewHierarchy(az)
		err := d.FromArchitecture(ctx, v, externalParent, "northeurope")
		if err != nil {
			errs.Add(fmt.Errorf("checkAllArchitectures: error deploying architecture %s: %w", v, err))
		}
	}
	if errs.HasErrors() {
		return errs
	}
	return nil
}
