// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"github.com/Masterminds/semver/v3"
)

// PolicyDefinitionVersions is a type alias for the generic collection.
type PolicyDefinitionVersions = VersionedPolicyCollection[*PolicyDefinition]

// NewPolicyDefinitionVersions creates a collection of PolicyDefinition.
func NewPolicyDefinitionVersions() *PolicyDefinitionVersions {
	return &PolicyDefinitionVersions{
		versions: make(map[semver.Version]*PolicyDefinition),
	}
}
