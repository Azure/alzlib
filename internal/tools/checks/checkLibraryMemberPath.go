// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

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
var CheckLibraryMemberPath = checker.NewValidatorCheck(
	"Library member path",
	checkLibraryMemberPath,
)

// ErrLibraryMemberPathMismatch is returned when the library member path does not match the expected path.
var ErrLibraryMemberPathMismatch = fmt.Errorf("library member path mismatch")

func checkLibraryMemberPath(in any) error {
	path, ok := os.LookupEnv(alzLibPathEnvVar)
	if !ok {
		return nil
	}

	metad, ok := in.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: %w expected *alzlib.AlzLib, got %T", ErrIncorrectType, in)
	}

	lastMetad := metad.Metadata()[len(metad.Metadata())-1]
	if lastMetad.Path() != path {
		return fmt.Errorf("checkLibraryMemberPath: %w: %s != %s", ErrLibraryMemberPathMismatch, lastMetad.Path(), path)
	}

	return nil
}
