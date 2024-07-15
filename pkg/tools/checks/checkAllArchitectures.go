package checks

import (
	"context"
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/pkg/deployment"
	"github.com/Azure/alzlib/pkg/tools/checker"
	"github.com/Azure/alzlib/pkg/tools/errcheck"
)

var CheckAllArchitectures = checker.NewValidatorCheck("All architectures are deployable", checkAllArchitectures)

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
