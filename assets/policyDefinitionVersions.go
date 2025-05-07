package assets

import (
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// PolicyDefinitionVersions is a collection of policy definition versions.
// Each policy definition version is identified by its version string.
// The name property must be identical for each policy definition version.
// Do not use this type directly; use the NewPolicyDefinitionVersions function to create an instance.
type PolicyDefinitionVersions struct {
	versions              map[semver.Version]*PolicyDefinitionVersion // map of policy definition version strings to policy definitions
	versionlessDefinition *PolicyDefinitionVersion                    // versionless policy definition
}

// NewPolicyDefinitionVersions creates a new PolicyDefinitionVersions instance.
// It initializes the versions map.
func NewPolicyDefinitionVersions() *PolicyDefinitionVersions {
	return &PolicyDefinitionVersions{
		versions: make(map[semver.Version]*PolicyDefinitionVersion),
	}
}

// Add adds a new policy definition version to the collection.
// If the same version already exists, it will error.
// If the version is empty, it will be treated as a versionless definition.
// Versionless and versioned definitions cannot be mixed.
// If the name property of the new version is different from the existing one, an error is returned.
func (pdvs *PolicyDefinitionVersions) Add(ver *PolicyDefinitionVersion) error {
	if ver == nil || ver.Properties == nil {
		return errors.New("PolicyDefinitionVersions.Add: cannot add nil policy definition or definition with nil properties")
	}

	// Add versionless definition if there are no versioned definitions
	verStr := ver.Version()
	if verStr == nil {
		if len(pdvs.versions) > 0 {
			return errors.New("PolicyDefinitionVersions.Add: cannot add versionless definition when versioned definitions already exist")
		}
		pdvs.versionlessDefinition = ver
		return nil
	}

	sv, err := semver.NewVersion(*verStr)
	if err != nil {
		return fmt.Errorf("PolicyDefinitionVersions.Add: invalid version string `%s` for policy %s. Inner error: %w", *verStr, *ver.Properties.DisplayName, err)
	}

	displayName := "unknown"
	if ver.Properties.DisplayName != nil {
		displayName = *ver.Properties.DisplayName
	}

	// Add versioned definition if there is no versionless definition
	if pdvs.versionlessDefinition != nil {
		return fmt.Errorf("PolicyDefinitionVersions.Add: cannot add versioned definition for policy %s when versionless definition already exists", displayName)
	}

	if _, ok := pdvs.versions[*sv]; ok {
		return fmt.Errorf("PolicyDefinitionVersions.Add: version %s for policy %s already exists", *verStr, displayName)
	}

	for v := range maps.Values(pdvs.versions) {
		if v.Properties.DisplayName == nil || *v.Properties.DisplayName != displayName {
			return fmt.Errorf("PolicyDefinitionVersions.Add: cannot add policy %s with nil name or different name than existing version %s", displayName, *v.Properties.DisplayName)
		}
	}

	pdvs.versions[*sv] = ver
	return nil
}

// GetVersion returns the policy definition version with the given version string.
// If the version is not found, it returns nil.
// If the version is empty, it returns the versionless definition.
func (pdvs *PolicyDefinitionVersions) GetVersion(versionConstr *string) (*PolicyDefinitionVersion, error) {
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

	var res *PolicyDefinitionVersion
	var resKey semver.Version
	for v, pd := range pdvs.versions {
		if !constraint.Check(&v) {
			continue
		}
		if res == nil {
			res = pd
			resKey = v
			continue
		}
		if !v.GreaterThan(&resKey) {
			continue
		}
		res = pd
		resKey = v
	}
	return res, nil
}

func policyVersionConstraintToSemVerConstraint(constraint string) (*semver.Constraints, error) {
	majorMinorPatch := strings.Split(constraint, ".")
	if len(majorMinorPatch) != 3 {
		return nil, fmt.Errorf("version constraint should have three dot-separated components `%s`.", constraint)
	}
	if majorMinorPatch[0] == "*" {
		return nil, fmt.Errorf("version constraint should not have wildcard in major version `%s`.", constraint)
	}
	if majorMinorPatch[2] != "*" {
		return nil, fmt.Errorf("version constraint should have wildcard in patch version `%s`.", constraint)
	}
	return semver.NewConstraint(constraint)
}
