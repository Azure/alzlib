// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package assets

import (
	"github.com/Masterminds/semver/v3"
)

// PolicySetDefinitionVersions represents a version collection of a policy set definitions.
type PolicySetDefinitionVersions = VersionedPolicyCollection[*PolicySetDefinitionVersion]

// NewPolicySetDefinitionVersions creates a collection of PolicySetDefinitionVersion.
func NewPolicySetDefinitionVersions() *PolicySetDefinitionVersions {
	return &PolicySetDefinitionVersions{
		versions: make(map[semver.Version]*PolicySetDefinitionVersion),
	}
}
