// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package parametername

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveExactMatch(t *testing.T) {
	t.Parallel()

	values := map[string]int{"dcrResourceId": 1, "DcrResourceId": 2}

	match, found, err := Resolve(values, "DcrResourceId")

	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "DcrResourceId", match.Key)
	assert.Equal(t, 2, match.Value)
}

func TestResolveCaseInsensitiveFallback(t *testing.T) {
	t.Parallel()

	values := map[string]int{"dcrResourceId": 1}

	match, found, err := Resolve(values, "DcrResourceId")

	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "dcrResourceId", match.Key, "the canonical key of the source artifact is returned")
	assert.Equal(t, 1, match.Value)
}

func TestResolveNotFound(t *testing.T) {
	t.Parallel()

	values := map[string]int{"dcrResourceId": 1}

	match, found, err := Resolve(values, "minPort")

	require.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, match.Key)
}

func TestResolveNilAndEmptyMap(t *testing.T) {
	t.Parallel()

	for name, values := range map[string]map[string]int{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, found, err := Resolve(values, "dcrResourceId")

			require.NoError(t, err)
			assert.False(t, found)
		})
	}
}

func TestResolveAmbiguousIsDeterministic(t *testing.T) {
	t.Parallel()

	values := map[string]int{"dcrResourceId": 1, "DCRRESOURCEID": 2}

	// Repeat to make sure the outcome does not depend on map iteration order.
	for range 100 {
		_, found, err := Resolve(values, "DcrResourceId")

		require.Error(t, err)
		assert.False(t, found)
		assert.Equal(
			t,
			"parameter name `DcrResourceId` is ambiguous, "+
				"it matches `DCRRESOURCEID`, `dcrResourceId` when compared case-insensitively",
			err.Error(),
		)
	}
}
