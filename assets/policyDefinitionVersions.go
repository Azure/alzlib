// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package assets

import (
	"github.com/Masterminds/semver/v3"
)

// PolicyDefinitionVersions is a type alias for the generic collection.
type PolicyDefinitionVersions = VersionedPolicyCollection[*PolicyDefinitionVersion]

// NewPolicyDefinitionVersions creates a collection of PolicyDefinitionVersion.
func NewPolicyDefinitionVersions() *PolicyDefinitionVersions {
	return &PolicyDefinitionVersions{
		versions: make(map[semver.Version]*PolicyDefinitionVersion),
	}
}
