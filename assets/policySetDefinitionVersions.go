// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"github.com/Masterminds/semver/v3"
)

// PolicySetDefinitionVersions represents a version collection of a policy set definitions.
type PolicySetDefinitionVersions = VersionedPolicyCollection[*PolicySetDefinition]

// NewPolicySetDefinitionVersions creates a collection of PolicySetDefinition.
func NewPolicySetDefinitionVersions() *PolicySetDefinitionVersions {
	return &PolicySetDefinitionVersions{
		versions:              make(map[semver.Version]*PolicySetDefinition),
		versionlessDefinition: nil,
	}
}
