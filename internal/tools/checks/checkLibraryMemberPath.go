// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"fmt"
	"os"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/tools/checker"
)

const (
	alzLibPathEnvVar = "LIBRARY_PATH"
)

func CheckLibraryMemberPath(inputs ...any) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"Library member path is correct",
		func() error {
			if len(inputs) != 1 {
				return fmt.Errorf("checkLibraryMemberPath: expected 1 input, got %d", len(inputs))
			}
			return checkLibraryMemberPath(inputs[0])
		},
	)
}

func checkLibraryMemberPath(in any) error {
	path, ok := os.LookupEnv(alzLibPathEnvVar)
	if !ok {
		return nil
	}
	metad, ok := in.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: expected *alzlib.AlzLib, got %T", in)
	}
	lastMetad := metad.Metadata()[len(metad.Metadata())-1]
	if lastMetad.Path() != path {
		return fmt.Errorf("checkLibraryMemberPath: path mismatch: %s != %s", lastMetad.Path(), path)
	}
	return nil
}
