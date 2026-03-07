// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"os"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/cache"
	"github.com/Azure/alzlib/deployment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cacheFile = "alzlib-cache.json.gz"

// TestCacheHitsAvoidAzureAPICalls verifies that the cache contains all built-in
// policy definitions referenced by the ALZ library. It does this by initializing
// with a local copy of the library and building the full hierarchy without an
// Azure policy client. If any built-in definition is missing from the cache,
// GetDefinitionsFromAzure (called internally by FromArchitecture) would fail
// with "policy client not set".
func TestCacheHitsAvoidAzureAPICalls(t *testing.T) {
	t.Parallel()

	f, err := os.Open(cacheFile)
	if os.IsNotExist(err) {
		t.Skipf("skipping: cache file %q not found", cacheFile)
	}
	require.NoError(t, err)

	defer f.Close()

	c, err := cache.NewCache(f)
	require.NoError(t, err)

	az := alzlib.NewAlzLib(nil)
	az.AddCache(c)

	// No policy client is set - this is intentional.
	// If the cache is complete, no Azure API calls are needed.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lib := alzlib.NewCustomLibraryReference("./testdata/alzlib-2025-09-0")
	require.NoError(t, az.Init(ctx, lib))

	// Build the full ALZ hierarchy. This triggers GetDefinitionsFromAzure for
	// every built-in policy referenced by the library's policy assignments.
	// Without a policy client, this will fail if any definition is not in the cache.
	h := deployment.NewHierarchy(az)
	require.NoError(t, h.FromArchitecture(ctx, "alz", "00000000-0000-0000-0000-000000000000", "testlocation"))

	// Verify the hierarchy was built successfully.
	assert.NotEmpty(t, h.ManagementGroupNames())
}

func TestCacheInitWithLibrary(t *testing.T) {
	t.Parallel()

	f, err := os.Open(cacheFile)
	if os.IsNotExist(err) {
		t.Skipf("skipping: cache file %q not found", cacheFile)
	}
	require.NoError(t, err)

	defer f.Close()

	c, err := cache.NewCache(f)
	require.NoError(t, err)

	az := alzlib.NewAlzLib(nil)
	az.AddCache(c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lib := alzlib.NewCustomLibraryReference("./testdata/simple-existingmg")
	require.NoError(t, az.Init(ctx, lib))

	// Library definitions should be present.
	assert.Contains(t, az.PolicyDefinitions(), "test-policy-definition")
	assert.Contains(t, az.PolicySetDefinitions(), "test-policy-set-definition")

	// Cached built-in definitions should also be present.
	assert.Greater(t, len(az.PolicyDefinitions()), 1)
	assert.Greater(t, len(az.PolicySetDefinitions()), 1)
}
