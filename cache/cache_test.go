// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gzipBytes compresses data with gzip and returns a reader over the result.
func gzipBytes(t *testing.T, data []byte) *bytes.Reader {
	t.Helper()

	var buf bytes.Buffer

	gw := gzip.NewWriter(&buf)

	_, err := gw.Write(data)
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	return bytes.NewReader(buf.Bytes())
}

// makePolicyDefinitionJSON returns JSON bytes for a minimal valid armpolicy.Definition.
func makePolicyDefinitionJSON(name, displayName, description string, version *string) json.RawMessage {
	def := armpolicy.Definition{
		Name: to.Ptr(name),
		Properties: &armpolicy.DefinitionProperties{
			DisplayName: to.Ptr(displayName),
			Description: to.Ptr(description),
			PolicyRule:  map[string]any{"if": map[string]any{"field": "type", "equals": "Microsoft.Resources/subscriptions"}, "then": map[string]any{"effect": "audit"}},
			Version:     version,
		},
	}

	data, _ := json.Marshal(def)

	return json.RawMessage(data)
}

// makePolicySetDefinitionJSON returns JSON bytes for a minimal valid armpolicy.SetDefinition.
func makePolicySetDefinitionJSON(name, displayName, description string, version *string) json.RawMessage {
	def := armpolicy.SetDefinition{
		Name: to.Ptr(name),
		Properties: &armpolicy.SetDefinitionProperties{
			DisplayName:       to.Ptr(displayName),
			Description:       to.Ptr(description),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
			Version:           version,
		},
	}

	data, _ := json.Marshal(def)

	return json.RawMessage(data)
}

func TestNewCacheRoundTrip(t *testing.T) {
	t.Parallel()

	versionless := makePolicyDefinitionJSON("test-pd", "Test Policy", "A test policy definition", nil)
	versionlessPsd := makePolicySetDefinitionJSON("test-psd", "Test Policy Set", "A test policy set definition", nil)

	cf := cacheFile{
		PolicyDefinitions: map[string]*cacheVersionsJSON{
			"test-pd": {
				Versionless: &versionless,
			},
		},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{
			"test-psd": {
				Versionless: &versionlessPsd,
			},
		},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	// Load the cache
	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)

	// Verify contents
	assert.Equal(t, 1, c.PolicyDefinitionNames())
	assert.Equal(t, 1, c.PolicySetDefinitionNames())
	assert.Equal(t, 1, c.PolicyDefinitionCount())
	assert.Equal(t, 1, c.PolicySetDefinitionCount())

	pdvs, ok := c.policyDefinitions["test-pd"]
	require.True(t, ok)

	pd, err := pdvs.GetVersion(nil)
	require.NoError(t, err)
	assert.Equal(t, "test-pd", *pd.Name)

	psdvs, ok := c.policySetDefinitions["test-psd"]
	require.True(t, ok)

	psd, err := psdvs.GetVersion(nil)
	require.NoError(t, err)
	assert.Equal(t, "test-psd", *psd.Name)

	// Round-trip: Save and reload
	var buf bytes.Buffer
	require.NoError(t, c.Save(&buf))

	c2, err := NewCache(&buf)
	require.NoError(t, err)

	assert.Equal(t, c.PolicyDefinitionNames(), c2.PolicyDefinitionNames())
	assert.Equal(t, c.PolicySetDefinitionNames(), c2.PolicySetDefinitionNames())
	assert.Equal(t, c.PolicyDefinitionCount(), c2.PolicyDefinitionCount())
	assert.Equal(t, c.PolicySetDefinitionCount(), c2.PolicySetDefinitionCount())
}

func TestNewCacheWithVersionedDefinitions(t *testing.T) {
	t.Parallel()

	v1 := makePolicyDefinitionJSON("test-pd", "Test Policy v1", "Version 1", to.Ptr("1.0.0"))
	v2 := makePolicyDefinitionJSON("test-pd", "Test Policy v2", "Version 2", to.Ptr("2.0.0"))

	cf := cacheFile{
		PolicyDefinitions: map[string]*cacheVersionsJSON{
			"test-pd": {
				Versions: map[string]json.RawMessage{
					"1.0.0": v1,
					"2.0.0": v2,
				},
			},
		},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)

	assert.Equal(t, 1, c.PolicyDefinitionNames())
	assert.Equal(t, 2, c.PolicyDefinitionCount())
	assert.Equal(t, 0, c.PolicySetDefinitionNames())
	assert.Equal(t, 0, c.PolicySetDefinitionCount())

	versions := c.PolicyDefinitionVersionsForName("test-pd")
	assert.Len(t, versions, 2)

	// Round-trip
	var buf bytes.Buffer
	require.NoError(t, c.Save(&buf))

	c2, err := NewCache(&buf)
	require.NoError(t, err)

	assert.Equal(t, c.PolicyDefinitionCount(), c2.PolicyDefinitionCount())
	assert.Equal(t, c.PolicyDefinitionNames(), c2.PolicyDefinitionNames())
}

func TestNewCacheWithVersionedSetDefinitions(t *testing.T) {
	t.Parallel()

	v1 := makePolicySetDefinitionJSON("test-psd", "Test PSD v1", "Version 1", to.Ptr("1.0.0"))
	v2 := makePolicySetDefinitionJSON("test-psd", "Test PSD v2", "Version 2", to.Ptr("2.0.0"))

	cf := cacheFile{
		PolicyDefinitions: map[string]*cacheVersionsJSON{},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{
			"test-psd": {
				Versions: map[string]json.RawMessage{
					"1.0.0": v1,
					"2.0.0": v2,
				},
			},
		},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)

	assert.Equal(t, 0, c.PolicyDefinitionNames())
	assert.Equal(t, 1, c.PolicySetDefinitionNames())
	assert.Equal(t, 2, c.PolicySetDefinitionCount())

	versions := c.PolicySetDefinitionVersionsForName("test-psd")
	assert.Len(t, versions, 2)
}

func TestNewCacheInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := NewCache(strings.NewReader("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating gzip reader")
}

func TestNewCacheNonCompliantPolicyDefinition(t *testing.T) {
	t.Parallel()

	// Missing fields that would fail validation (e.g. no displayName, description, policyRule).
	// The cache should still load these because Azure built-in definitions
	// may not comply with documented property constraints.
	raw := json.RawMessage(`{"name":"test","properties":{}}`)
	cf := cacheFile{
		PolicyDefinitions: map[string]*cacheVersionsJSON{
			"test": {
				Versionless: &raw,
			},
		},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)
	assert.Equal(t, 1, c.PolicyDefinitionNames())
}

func TestNewCacheNonCompliantPolicySetDefinition(t *testing.T) {
	t.Parallel()

	// Missing fields that would fail validation (e.g. no displayName, description).
	// The cache should still load these because Azure built-in definitions
	// may not comply with documented property constraints.
	raw := json.RawMessage(`{"name":"test","properties":{}}`)
	cf := cacheFile{
		PolicyDefinitions: map[string]*cacheVersionsJSON{},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{
			"test": {
				Versionless: &raw,
			},
		},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)
	assert.Equal(t, 1, c.PolicySetDefinitionNames())
}

func TestNewCacheEmptyFile(t *testing.T) {
	t.Parallel()

	cf := cacheFile{
		PolicyDefinitions:    map[string]*cacheVersionsJSON{},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)

	assert.Equal(t, 0, c.PolicyDefinitionNames())
	assert.Equal(t, 0, c.PolicySetDefinitionNames())
	assert.Equal(t, 0, c.PolicyDefinitionCount())
	assert.Equal(t, 0, c.PolicySetDefinitionCount())
}

func TestPolicyDefinitionVersionsForNameNotFound(t *testing.T) {
	t.Parallel()

	cf := cacheFile{
		PolicyDefinitions:    map[string]*cacheVersionsJSON{},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)

	assert.Nil(t, c.PolicyDefinitionVersionsForName("nonexistent"))
	assert.Nil(t, c.PolicySetDefinitionVersionsForName("nonexistent"))
}

func TestCacheMixedDefinitions(t *testing.T) {
	t.Parallel()

	// Multiple policy definitions (some versionless, some versioned) and policy set definitions.
	versionless := makePolicyDefinitionJSON("pd-versionless", "Versionless PD", "A versionless pd", nil)
	v1 := makePolicyDefinitionJSON("pd-versioned", "Versioned PD v1", "Version 1", to.Ptr("1.0.0"))
	v2 := makePolicyDefinitionJSON("pd-versioned", "Versioned PD v2", "Version 2", to.Ptr("2.0.0"))
	psd := makePolicySetDefinitionJSON("psd-one", "PSD One", "First set", nil)

	cf := cacheFile{
		PolicyDefinitions: map[string]*cacheVersionsJSON{
			"pd-versionless": {
				Versionless: &versionless,
			},
			"pd-versioned": {
				Versions: map[string]json.RawMessage{
					"1.0.0": v1,
					"2.0.0": v2,
				},
			},
		},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{
			"psd-one": {
				Versionless: &psd,
			},
		},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)

	assert.Equal(t, 2, c.PolicyDefinitionNames())
	assert.Equal(t, 3, c.PolicyDefinitionCount()) // 1 versionless + 2 versioned
	assert.Equal(t, 1, c.PolicySetDefinitionNames())
	assert.Equal(t, 1, c.PolicySetDefinitionCount())

	// Round-trip
	var buf bytes.Buffer
	require.NoError(t, c.Save(&buf))

	c2, err := NewCache(&buf)
	require.NoError(t, err)

	assert.Equal(t, c.PolicyDefinitionNames(), c2.PolicyDefinitionNames())
	assert.Equal(t, c.PolicyDefinitionCount(), c2.PolicyDefinitionCount())
	assert.Equal(t, c.PolicySetDefinitionNames(), c2.PolicySetDefinitionNames())
	assert.Equal(t, c.PolicySetDefinitionCount(), c2.PolicySetDefinitionCount())
}

func TestPolicyDefinitionsAccessor(t *testing.T) {
	t.Parallel()

	versionless := makePolicyDefinitionJSON("test-pd", "Test PD", "Test policy def", nil)
	cf := cacheFile{
		PolicyDefinitions: map[string]*cacheVersionsJSON{
			"test-pd": {
				Versionless: &versionless,
			},
		},
		PolicySetDefinitions: map[string]*cacheVersionsJSON{},
	}

	data, err := json.Marshal(cf)
	require.NoError(t, err)

	c, err := NewCache(gzipBytes(t, data))
	require.NoError(t, err)

	pds := c.PolicyDefinitions()
	assert.Len(t, pds, 1)
	assert.Contains(t, pds, "test-pd")

	psds := c.PolicySetDefinitions()
	assert.Empty(t, psds)
}
