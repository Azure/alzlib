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

// CheckLibraryMemberPath is a validator check that ensures the library member path matches the
// expected path from the environment variable.
func CheckLibraryMemberPath(az *alzlib.AlzLib) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"Library member path",
		checkLibraryMemberPath(az),
	)
}

// ErrLibraryMemberPathMismatch is returned when the library member path does not match the expected path.
var ErrLibraryMemberPathMismatch = fmt.Errorf("library member path mismatch")

func checkLibraryMemberPath(az *alzlib.AlzLib) func() error {
	return func() error {
		path, ok := os.LookupEnv(alzLibPathEnvVar)
		if !ok {
			return nil
		}

		lastMetad := az.Metadata()[len(az.Metadata())-1]
		if lastMetad.Path() != path {
			return fmt.Errorf("checkLibraryMemberPath: %w: %s != %s", ErrLibraryMemberPathMismatch, lastMetad.Path(), path)
		}

		return nil
	}
}
