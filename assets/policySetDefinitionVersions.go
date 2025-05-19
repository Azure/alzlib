package assets

import (
	"github.com/Masterminds/semver/v3"
)

type PolicySetDefinitionVersions = VersionedPolicyCollection[*PolicySetDefinitionVersion]

func NewPolicySetDefinitionVersions() *PolicySetDefinitionVersions {
	return &PolicySetDefinitionVersions{
		versions: make(map[semver.Version]*PolicySetDefinitionVersion),
	}
}
