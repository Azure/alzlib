package assets

import (
	"errors"
	"fmt"
	"maps"

	"github.com/Masterminds/semver/v3"
)

// Check PolicySetDefinitionVersions implements the PolicyDefinitionVersion interface

// PolicySetDefinitionVersions is a collection of policy set definition versions.
// Each policy definition version is identified by its version string.
// The name property must be identical for each policy definition version.
// Do not use this type directly; use the NewPolicyDefinitionVersions function to create an instance.
type PolicySetDefinitionVersions struct {
	versions              map[semver.Version]*PolicySetDefinitionVersion // map of policy definition version strings to policy definitions
	versionlessDefinition *PolicySetDefinitionVersion                    // versionless policy definition
}

// NewPolicySetDefinitionVersions creates a new PolicyDefinitionVersions instance.
// It initializes the versions map.
func NewPolicySetDefinitionVersions() *PolicySetDefinitionVersions {
	return &PolicySetDefinitionVersions{
		versions: make(map[semver.Version]*PolicySetDefinitionVersion),
	}
}

// Add adds a new policy set definition version to the collection.
// If the same version already exists, it will error.
// If the version is empty, it will be treated as a versionless definition.
// Versionless and versioned definitions cannot be mixed.
// If the name property of the new version is different from the existing one, an error is returned.
func (pdvs *PolicySetDefinitionVersions) Add(ver *PolicySetDefinitionVersion) error {
	if ver == nil || ver.Properties == nil {
		return errors.New("PolicySetDefinitionVersions.Add: cannot add nil policy definition or definition with nil properties")
	}

	// Add versionless definition if there are no versioned definitions
	verStr := ver.Version()
	if verStr == nil {
		if len(pdvs.versions) > 0 {
			return errors.New("PolicySetDefinitionVersions.Add: cannot add versionless definition when versioned definitions already exist")
		}
		pdvs.versionlessDefinition = ver
		return nil
	}

	sv, err := semver.NewVersion(*verStr)
	if err != nil {
		return fmt.Errorf("PolicySetDefinitionVersions.Add: invalid version string `%s` for policy %s. Inner error: %w", *verStr, *ver.Properties.DisplayName, err)
	}

	displayName := "unknown"
	if ver.Properties.DisplayName != nil {
		displayName = *ver.Properties.DisplayName
	}

	// Add versioned definition if there is no versionless definition
	if pdvs.versionlessDefinition != nil {
		return fmt.Errorf("PolicySetDefinitionVersions.Add: cannot add versioned definition for policy %s when versionless definition already exists", displayName)
	}

	if _, ok := pdvs.versions[*sv]; ok {
		return fmt.Errorf("PolicySetDefinitionVersions.Add: version %s for policy %s already exists", *verStr, displayName)
	}

	for v := range maps.Values(pdvs.versions) {
		if v.Properties.DisplayName == nil || *v.Properties.DisplayName != displayName {
			return fmt.Errorf("PolicySetDefinitionVersions.Add: cannot add policy %s with nil name or different name than existing version %s", displayName, *v.Properties.DisplayName)
		}
	}

	pdvs.versions[*sv] = ver
	return nil
}

// GetVersion returns the policy definition version with the given version string.
// If the version is not found, it returns nil.
// If the version is empty, it returns the versionless definition.
func (pdvs *PolicySetDefinitionVersions) GetVersion(versionConstr *string) (*PolicySetDefinitionVersion, error) {
	var constraint *semver.Constraints
	if versionConstr == nil || *versionConstr == "" {
		if pdvs.versionlessDefinition != nil {
			return pdvs.versionlessDefinition, nil
		}
		constraint, _ = semver.NewConstraint(">= 0.0.0")
	}

	if versionConstr != nil {
		if *versionConstr != "" {
			constraint2, err := policyVersionConstraintToSemVerConstraint(*versionConstr)
			if err != nil {
				return nil, err
			}
			if constraint2 != nil {
				constraint = constraint2
			}
		}
	}

	var res *PolicySetDefinitionVersion
	var resKey semver.Version
	for v, pd := range pdvs.versions {
		if !constraint.Check(&v) || !semverCheckPrereleaseStrict(&v, constraint) {
			continue
		}
		if res == nil {
			res = pd
			resKey = v
			continue
		}
		if v.LessThan(&resKey) {
			continue
		}
		res = pd
		resKey = v
	}
	return res, nil
}
