// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"context"
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/hashicorp/go-multierror"
)

// CheckAllArchitectures is a validator check that ensures all architectures in the ALZ library are deployable.
func CheckAllArchitectures(az *alzlib.AlzLib) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"All architectures are deployable",
		checkAllArchitectures(az),
	)
}

func checkAllArchitectures(az *alzlib.AlzLib) func() error {
	return func() error {
		archs := az.Architectures()

		var errs error

		externalParent := "00000000-0000-0000-0000-000000000000"
		ctx := context.Background()

		for _, v := range archs {
			d := deployment.NewHierarchy(az)

			err := d.FromArchitecture(ctx, v, externalParent, "northeurope")
			if err != nil {
				errs = multierror.Append(errs, fmt.Errorf("checkAllArchitectures: deploying architecture %s: %w", v, err))
			}
		}

		return errs
	}
}
