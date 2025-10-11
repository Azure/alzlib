// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"errors"
	"fmt"
	"iter"
	"maps"

	"github.com/Azure/alzlib/to"
	"github.com/Masterminds/semver/v3"
	"github.com/brunoga/deep"
	"github.com/hashicorp/go-multierror"
)

var (
	ErrNoVersionFound = errors.New("no version found")
)

// VersionedTypes is a type constraint for versioned policy types.
type VersionedTypes interface {
	*PolicyDefinition | *PolicySetDefinition
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

		// Try a release version first
		release, err := c.GetVersion(to.Ptr(">= 0.0.*"))
		if err != nil {
			if !errors.Is(err, ErrNoVersionFound) {
				return nil, err
			}
		}

		if release != nil {
			return release, nil
		}

		// If no release version found, try a preview version
		return c.GetVersion(to.Ptr(">= 0.0.*-preview"))
	}

	constraint, err := policyVersionConstraintToSemVerConstraint(*constraintStr)
	if err != nil {
		return nil, err
	}

	var resKey *semver.Version

	for v := range maps.Keys(c.versions) {
		if !constraint.Check(&v) {
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
		return nil, errors.Join(ErrNoVersionFound, fmt.Errorf(
			"constraint %s",
			*constraintStr,
		))
	}

	return c.versions[*resKey], nil
}

// GetVersionStrict returns a policy version based on the exact version string.
// If the version string is nil, it returns the versionless definition if it exists.
// If the version string is nil and no versionless definition exists it returns the exact match, or an error if no exact match exists.
func (c *VersionedPolicyCollection[T]) GetVersionStrict(ver *string) (T, error) {
	if ver != nil && *ver == "" {
		return nil, errors.New("version string cannot be empty")
	}

	if ver == nil {
		if c.versionlessDefinition == nil {
			return nil, errors.New("no versionless definition exists")
		}
		return c.versionlessDefinition, nil
	}

	strictVer, err := semver.StrictNewVersion(*ver)
	if err != nil {
		return nil, fmt.Errorf("invalid version string `%s`. %w", *ver, err)
	}
	policy, ok := c.versions[*strictVer]
	if !ok {
		return nil, fmt.Errorf("no version found for version %s", *ver)
	}
	return policy, nil
}

// Add adds a new version to the collection.
func (c *VersionedPolicyCollection[T]) Add(add T, overwrite bool) error {
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

		cpy := deep.MustCopy(add)
		c.versionlessDefinition = cpy

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

	if _, ok := c.versions[*sv]; ok && !overwrite {
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

	cpy := deep.MustCopy(add)
	c.versions[*sv] = cpy

	return nil
}

// Exists checks if a version or versionless definition exists in the collection.
// If version is nil, it checks for the existence of a versionless definition.
// You must supply a exact semver version string to check for a specific version.
// If you want to supply a version constraint, use GetVersion instead.
func (c *VersionedPolicyCollection[T]) Exists(version *string) bool {
	if version == nil {
		return c.versionlessDefinition != nil
	}

	sv, err := semver.StrictNewVersion(*version)
	if err != nil {
		return false
	}

	_, ok := c.versions[*sv]
	return ok
}

func (c *VersionedPolicyCollection[T]) AllVersions() iter.Seq[T] {
	if c.versionlessDefinition != nil {
		return func(yield func(T) bool) {
			if !yield(c.versionlessDefinition) {
				return
			}
		}
	}
	return maps.Values(c.versions)
}

// Upsert merges another VersionedPolicyCollection into this one.
// If overwrite is true, existing versions will be overwritten.
// If overwrite is false, an error will be returned if a version already exists.
func (c *VersionedPolicyCollection[T]) Upsert(in *VersionedPolicyCollection[T], overwrite bool) error {
	if in == nil || (in.versionlessDefinition == nil && len(in.versions) == 0) {
		return nil
	}

	// if the incoming collection has a versionless definition, we need to handle that first
	if in.versionlessDefinition != nil {
		return c.Add(in.versionlessDefinition, overwrite)
	}

	if c.versions == nil {
		c.versions = make(map[semver.Version]T)
	}

	var merr error
	// We now need to merge the versioned definitions
	for _, def := range in.versions {
		if err := c.Add(def, overwrite); err != nil {
			merr = multierror.Append(merr, err)
		}
	}

	return merr
}
