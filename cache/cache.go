// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"maps"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Masterminds/semver/v3"
)

const (
	cacheBufferMaxSize = 200 * 1024 * 1024 // 200 MB
)

// Cache stores built-in Azure policy definitions and policy set definitions.
// It is used to pre-populate AlzLib's internal maps to avoid Azure API calls.
type Cache struct {
	policyDefinitions    map[string]*assets.PolicyDefinitionVersions
	policySetDefinitions map[string]*assets.PolicySetDefinitionVersions

	policyDefinitionCount    int
	policySetDefinitionCount int
}

// cacheFile is the JSON serialization structure for the cache.
type cacheFile struct {
	PolicyDefinitions    map[string]*cacheVersionsJSON `json:"policyDefinitions"`
	PolicySetDefinitions map[string]*cacheVersionsJSON `json:"policySetDefinitions"`
}

// cacheVersionsJSON represents the JSON structure for a versioned policy collection.
type cacheVersionsJSON struct {
	Versionless *json.RawMessage           `json:"versionless,omitempty"`
	Versions    map[string]json.RawMessage `json:"versions,omitempty"`
}

// NewCache deserializes a cache from the given reader.
// The reader should contain JSON data previously written by [Cache.Save].
// Definitions are not validated on load because Azure built-in definitions
// may not comply with documented property constraints.
func NewCache(r io.Reader) (*Cache, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("cache.NewCache: creating gzip reader: %w", err)
	}
	defer gr.Close() //nolint:errcheck - best effort to release resources, no error handling needed

	lr := io.LimitReader(gr, cacheBufferMaxSize)

	var cf cacheFile
	if err := json.NewDecoder(lr).Decode(&cf); err != nil {
		return nil, fmt.Errorf("cache.NewCache: decoding cache: %w", err)
	}

	c := &Cache{
		policyDefinitions:    make(map[string]*assets.PolicyDefinitionVersions, len(cf.PolicyDefinitions)),
		policySetDefinitions: make(map[string]*assets.PolicySetDefinitionVersions, len(cf.PolicySetDefinitions)),
	}

	for name, versions := range cf.PolicyDefinitions {
		if versions == nil {
			continue
		}

		pdvs := assets.NewPolicyDefinitionVersions()

		if versions.Versionless != nil {
			var def armpolicy.Definition
			if err := json.Unmarshal(*versions.Versionless, &def); err != nil {
				return nil, fmt.Errorf("cache.NewCache: unmarshaling versionless policy definition %s: %w", name, err)
			}

			pd := assets.NewPolicyDefinition(def)

			if err := pdvs.Add(pd, false); err != nil {
				return nil, fmt.Errorf("cache.NewCache: adding versionless policy definition %s: %w", name, err)
			}
		}

		for ver, raw := range versions.Versions {
			var def armpolicy.Definition
			if err := json.Unmarshal(raw, &def); err != nil {
				return nil, fmt.Errorf("cache.NewCache: unmarshaling policy definition %s version %s: %w", name, ver, err)
			}

			pd := assets.NewPolicyDefinition(def)

			if err := pdvs.Add(pd, false); err != nil {
				return nil, fmt.Errorf("cache.NewCache: adding policy definition %s version %s: %w", name, ver, err)
			}
		}

		c.policyDefinitions[name] = pdvs
	}

	for name, versions := range cf.PolicySetDefinitions {
		if versions == nil {
			continue
		}

		psdvs := assets.NewPolicySetDefinitionVersions()

		if versions.Versionless != nil {
			var def armpolicy.SetDefinition
			if err := json.Unmarshal(*versions.Versionless, &def); err != nil {
				return nil, fmt.Errorf("cache.NewCache: unmarshaling versionless policy set definition %s: %w", name, err)
			}

			psd := assets.NewPolicySetDefinition(def)

			if err := psdvs.Add(psd, false); err != nil {
				return nil, fmt.Errorf("cache.NewCache: adding versionless policy set definition %s: %w", name, err)
			}
		}

		for ver, raw := range versions.Versions {
			var def armpolicy.SetDefinition
			if err := json.Unmarshal(raw, &def); err != nil {
				return nil, fmt.Errorf("cache.NewCache: unmarshaling policy set definition %s version %s: %w", name, ver, err)
			}

			psd := assets.NewPolicySetDefinition(def)

			if err := psdvs.Add(psd, false); err != nil {
				return nil, fmt.Errorf("cache.NewCache: adding policy set definition %s version %s: %w", name, ver, err)
			}
		}

		c.policySetDefinitions[name] = psdvs
	}

	c.computeCounts()

	return c, nil
}

// computeCounts calculates and stores the total version counts for
// policy definitions and policy set definitions.
func (c *Cache) computeCounts() {
	c.policyDefinitionCount = 0
	for _, pdvs := range c.policyDefinitions {
		for range pdvs.AllVersions() {
			c.policyDefinitionCount++
		}
	}

	c.policySetDefinitionCount = 0
	for _, psdvs := range c.policySetDefinitions {
		for range psdvs.AllVersions() {
			c.policySetDefinitionCount++
		}
	}
}

// Save serializes the cache to the given writer as JSON.
func (c *Cache) Save(w io.Writer) error {
	cf := cacheFile{
		PolicyDefinitions:    make(map[string]*cacheVersionsJSON, len(c.policyDefinitions)),
		PolicySetDefinitions: make(map[string]*cacheVersionsJSON, len(c.policySetDefinitions)),
	}

	for name, pdvs := range c.policyDefinitions {
		cvj := &cacheVersionsJSON{}

		for pd := range pdvs.AllVersions() {
			raw, err := json.Marshal(pd.Definition)
			if err != nil {
				return fmt.Errorf("cache.Save: marshaling policy definition %s: %w", name, err)
			}

			rawMsg := json.RawMessage(raw)

			if pd.GetVersion() == nil {
				cvj.Versionless = &rawMsg
			} else {
				if cvj.Versions == nil {
					cvj.Versions = make(map[string]json.RawMessage)
				}

				cvj.Versions[*pd.GetVersion()] = rawMsg
			}
		}

		cf.PolicyDefinitions[name] = cvj
	}

	for name, psdvs := range c.policySetDefinitions {
		cvj := &cacheVersionsJSON{}

		for psd := range psdvs.AllVersions() {
			raw, err := json.Marshal(psd.SetDefinition)
			if err != nil {
				return fmt.Errorf("cache.Save: marshaling policy set definition %s: %w", name, err)
			}

			rawMsg := json.RawMessage(raw)

			if psd.GetVersion() == nil {
				cvj.Versionless = &rawMsg
			} else {
				if cvj.Versions == nil {
					cvj.Versions = make(map[string]json.RawMessage)
				}

				cvj.Versions[*psd.GetVersion()] = rawMsg
			}
		}

		cf.PolicySetDefinitions[name] = cvj
	}

	gw := gzip.NewWriter(w)

	enc := json.NewEncoder(gw)

	if err := enc.Encode(cf); err != nil {
		return fmt.Errorf("cache.Save: encoding cache: %w", err)
	}

	if err := gw.Close(); err != nil {
		return fmt.Errorf("cache.Save: closing gzip writer: %w", err)
	}

	return nil
}

// PolicyDefinitions returns a shallow copy of the cached policy definition version collections map.
func (c *Cache) PolicyDefinitions() map[string]*assets.PolicyDefinitionVersions {
	return maps.Clone(c.policyDefinitions)
}

// PolicySetDefinitions returns a shallow copy of the cached policy set definition version collections map.
func (c *Cache) PolicySetDefinitions() map[string]*assets.PolicySetDefinitionVersions {
	return maps.Clone(c.policySetDefinitions)
}

// PolicyDefinitionCount returns the total number of policy definitions in the cache,
// counting each version separately.
func (c *Cache) PolicyDefinitionCount() int {
	return c.policyDefinitionCount
}

// PolicySetDefinitionCount returns the total number of policy set definitions in the cache,
// counting each version separately.
func (c *Cache) PolicySetDefinitionCount() int {
	return c.policySetDefinitionCount
}

// PolicyDefinitionNames returns the number of unique policy definition names in the cache.
func (c *Cache) PolicyDefinitionNames() int {
	return len(c.policyDefinitions)
}

// PolicySetDefinitionNames returns the number of unique policy set definition names in the cache.
func (c *Cache) PolicySetDefinitionNames() int {
	return len(c.policySetDefinitions)
}

// PolicyDefinitionVersionsForName returns all semver versions for a given policy definition name.
func (c *Cache) PolicyDefinitionVersionsForName(name string) []semver.Version {
	pdvs, ok := c.policyDefinitions[name]
	if !ok {
		return nil
	}

	return pdvs.Versions()
}

// PolicySetDefinitionVersionsForName returns all semver versions for a given policy set definition name.
func (c *Cache) PolicySetDefinitionVersionsForName(name string) []semver.Version {
	psdvs, ok := c.policySetDefinitions[name]
	if !ok {
		return nil
	}

	return psdvs.Versions()
}
