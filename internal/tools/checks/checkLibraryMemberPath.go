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
	alzLibPathEnvVar = "ALZLIB_PATH"
)

var CheckLibraryMemberPath = checker.NewValidatorCheck("Library member path", checkLibraryMemberPath)

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
