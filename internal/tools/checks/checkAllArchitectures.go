// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package checks

import (
	"context"
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/internal/tools/errcheck"
)

// CheckAllArchitectures is a validator check that ensures all architectures in the ALZ library are deployable.
var CheckAllArchitectures = checker.NewValidatorCheck(
	"All architectures are deployable",
	checkAllArchitectures,
)

func checkAllArchitectures(azany any) error {
	az, ok := azany.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: expected *alzlib.AlzLib, got %T", azany)
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
