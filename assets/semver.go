// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	// ExpectedVersionComponents is the number of components expected in a semantic version.
	ExpectedVersionComponents = 3
)

var (
	// ErrVersionConstraintInvalid is returned when the version constraint is invalid.
	ErrVersionConstraintInvalid = errors.New("version constraint is invalid")
)

// policyVersionConstraintToSemVerConstraint converts a policy version constraint string to a semver
// constraint.
// It ensures that the major version is not a wildcard and that the patch version is a wildcard.
func policyVersionConstraintToSemVerConstraint(constraint string) (*semver.Constraints, error) {
	majorMinorPatch := strings.Split(constraint, ".")
	if len(majorMinorPatch) != ExpectedVersionComponents {
		return nil, fmt.Errorf(
			"version constraint should have three dot-separated components `%s`",
			constraint,
		)
	}

	if majorMinorPatch[0] == "*" {
		return nil, fmt.Errorf(
			"version constraint should not have wildcard in major version `%s`",
			constraint,
		)
	}

	if before, _, _ := strings.Cut(majorMinorPatch[2], "-"); before != "*" {
		return nil, fmt.Errorf(
			"version constraint should have wildcard in patch version `%s`",
			constraint,
		)
	}

	sv, err := semver.NewConstraint(constraint)
	if err != nil {
		return nil, errors.Join(ErrVersionConstraintInvalid, err)
	}

	return sv, nil
}

// semverCheckPrereleaseStrict checks if the version's prerelease matches the constraint's
// prerelease.
// We need this as the semver package does not support this directly.
// It works for simple constraints like "1.0.*-alpha", which will match "1.0.0-alpha".
// It does not work for multiple comma separated constraints like "1.0.0-alpha, 1.0.0-beta".
func semverCheckPrereleaseStrict(v *semver.Version, c *semver.Constraints) bool {
	conStr := c.String()
	_, after, _ := strings.Cut(conStr, "-")

	return v.Prerelease() == after
}
