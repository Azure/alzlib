// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestVersionedPolicyCollectionVersionsNilReceiver ensures that Versions can describe a definition that
// was never stored, see Azure/Azure-Landing-Zones#4327.
func TestVersionedPolicyCollectionVersionsNilReceiver(t *testing.T) {
	t.Parallel()

	var (
		pdvs  *PolicyDefinitionVersions
		psdvs *PolicySetDefinitionVersions
	)

	assert.NotPanics(t, func() { assert.Empty(t, pdvs.Versions()) })
	assert.NotPanics(t, func() { assert.Empty(t, psdvs.Versions()) })
}
