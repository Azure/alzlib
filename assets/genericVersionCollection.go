// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"errors"
	"fmt"
	"maps"

	"github.com/Azure/alzlib/to"
	"github.com/Masterminds/semver/v3"
)

// VersionedTypes is a type constraint for versioned policy types.
type VersionedTypes interface {
	*PolicyDefinitionVersion | *PolicySetDefinitionVersion
}

// Versioned is an interface for versioned policy types.
type Versioned interface {
	VersionedTypes
	GetVersion() *string
	GetName() *string
}

// VersionedPolicyCollection is a generic collection of versioned policies.
type VersionedPolicyCollection[T Versioned] struct {
	versions              map[semver.Version]T
	versionlessDefinition T
}

// GetVersion returns a policy version based on the provided constraint string.
// If the constraint string is nil, it returns the versionless definition if it exists.
// If the constraint string is nil and no versionless definition exists, it returns the latest
// version.
func (c *VersionedPolicyCollection[T]) GetVersion(constraintStr *string) (T, error) {
	if constraintStr != nil && *constraintStr == "" {
		return nil, errors.New("constraint string cannot be empty")
	}

	if constraintStr == nil {
		if c.versionlessDefinition != nil {
			return c.versionlessDefinition, nil
		}

		return c.GetVersion(to.Ptr(">= 0.0.*"))
	}

	constraint, err := policyVersionConstraintToSemVerConstraint(*constraintStr)
	if err != nil {
		return nil, err
	}

	var resKey *semver.Version

	for v := range maps.Keys(c.versions) {
		if !constraint.Check(&v) || !semverCheckPrereleaseStrict(&v, constraint) {
			continue
		}

		if resKey == nil {
			resKey = &v
			continue
		}

		if v.LessThan(resKey) {
			continue
		}

		resKey = &v
	}

	if resKey == nil {
		return nil, fmt.Errorf("no version found for constraint %s", *constraintStr)
	}

	return c.versions[*resKey], nil
}

// Add adds a new version to the collection.
func (c *VersionedPolicyCollection[T]) Add(add T) error {
	if add == nil {
		return errors.New("cannot add nil policy definition")
	}

	verStr := add.GetVersion()
	if verStr == nil {
		if len(c.versions) > 0 {
			return errors.New(
				"cannot add versionless definition when versioned definitions already exist",
			)
		}

		if c.versionlessDefinition != nil {
			return errors.New(
				"cannot add versionless definition when versionless definition already exists",
			)
		}

		c.versionlessDefinition = add

		return nil
	}

	name := add.GetName()

	sv, err := semver.NewVersion(*verStr)
	if err != nil {
		return fmt.Errorf("invalid version string `%s`. %w", *verStr, err)
	}

	if c.versionlessDefinition != nil {
		return errors.New(
			"cannot add versioned definition when versionless definition(s) already exists",
		)
	}

	if _, ok := c.versions[*sv]; ok {
		return fmt.Errorf("version %s for %s already exists", *verStr, *name)
	}

	for v := range maps.Values(c.versions) {
		if *v.GetName() != *name {
			return fmt.Errorf(
				"cannot add with different name than existing version. Add name is `%s`. Existing name is `%s`",
				*name,
				*v.GetName(),
			)
		}
	}

	c.versions[*sv] = add

	return nil
}
