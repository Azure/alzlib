// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// NewCacheFromAzure scans an Azure tenant for all built-in policy definitions and
// policy set definitions and returns a populated [Cache].
// The client factory must be configured with appropriate credentials.
// If logger is nil, no log output is produced.
func NewCacheFromAzure(ctx context.Context, client *armpolicy.ClientFactory, logger *slog.Logger) (*Cache, error) {
	if client == nil {
		return nil, fmt.Errorf("cache.NewCacheFromAzure: client factory is nil")
	}

	if logger == nil {
		logger = slog.New(discardHandler{})
	}

	c := &Cache{
		policyDefinitions:    make(map[string]*assets.PolicyDefinitionVersions),
		policySetDefinitions: make(map[string]*assets.PolicySetDefinitionVersions),
	}

	logger.Info("fetching policy definition versions (bulk)")

	if err := c.fetchPolicyDefinitions(ctx, client, logger); err != nil {
		return nil, err
	}

	logger.Info("fetching policy set definitions")

	if err := c.fetchPolicySetDefinitions(ctx, client, logger); err != nil {
		return nil, err
	}

	// The bulk ListAllBuiltins API for policy definitions only returns the latest version
	// for each definition. Library-defined (custom) policy set definitions may reference
	// older major versions of built-in policy definitions that are not included in the
	// bulk response. Since we can't predict which versions library PSDs will need, fetch
	// all historical versions for every versioned policy definition.
	if err := c.fetchAllHistoricalPolicyDefinitionVersions(ctx, client, logger); err != nil {
		return nil, err
	}

	c.computeCounts()

	logger.Info("cache complete",
		slog.Int("policy_definition_names", len(c.policyDefinitions)),
		slog.Int("policy_definition_versions", c.policyDefinitionCount),
		slog.Int("policy_set_definition_names", len(c.policySetDefinitions)),
		slog.Int("policy_set_definition_versions", c.policySetDefinitionCount),
	)

	return c, nil
}

// fetchPolicyDefinitions fetches all built-in policy definition versions in a single call
// and groups them by policy definition name.
// It then lists all built-in definitions using the versionless client and adds any that
// were not returned by the versioned API as versionless definitions.
func (c *Cache) fetchPolicyDefinitions(ctx context.Context, client *armpolicy.ClientFactory, logger *slog.Logger) error {
	verClient := client.NewDefinitionVersionsClient()

	resp, err := verClient.ListAllBuiltins(ctx, nil)
	if err != nil {
		return fmt.Errorf("cache.NewCacheFromAzure: listing all built-in policy definition versions: %w", err)
	}

	for _, v := range resp.Value {
		if v == nil {
			continue
		}

		pd, err := assets.NewPolicyDefinitionFromVersion(*v)
		if err != nil {
			return fmt.Errorf(
				"cache.NewCacheFromAzure: converting built-in policy definition version: %w",
				err,
			)
		}

		name := pd.GetName()
		if name == nil {
			continue
		}

		pdvs, ok := c.policyDefinitions[*name]
		if !ok {
			pdvs = assets.NewPolicyDefinitionVersions()
			c.policyDefinitions[*name] = pdvs
		}

		if err := pdvs.Add(pd, false); err != nil {
			return fmt.Errorf(
				"cache.NewCacheFromAzure: adding built-in policy definition version for %s: %w",
				*name,
				err,
			)
		}
	}

	logger.Info("fetched versioned policy definitions",
		slog.Int("count", len(c.policyDefinitions)),
	)

	// Fetch all built-in definitions using the versionless client and add any that
	// were not returned by the versioned API. Some built-in definitions are not yet
	// available via the versioned API but are still referenced by ALZ library assignments.
	defClient := client.NewDefinitionsClient()
	pager := defClient.NewListBuiltInPager(nil)

	versionlessCount := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("cache.NewCacheFromAzure: listing built-in policy definitions: %w", err)
		}

		for _, def := range page.Value {
			if def == nil || def.Name == nil {
				continue
			}

			if _, exists := c.policyDefinitions[*def.Name]; exists {
				continue
			}

			pd := assets.NewPolicyDefinition(*def)
			pdvs := assets.NewPolicyDefinitionVersions()

			if err := pdvs.Add(pd, false); err != nil {
				return fmt.Errorf(
					"cache.NewCacheFromAzure: adding versionless built-in policy definition for %s: %w",
					*def.Name,
					err,
				)
			}

			c.policyDefinitions[*def.Name] = pdvs
			versionlessCount++
		}
	}

	logger.Info("fetched versionless policy definitions",
		slog.Int("added", versionlessCount),
		slog.Int("total", len(c.policyDefinitions)),
	)

	return nil
}

// fetchPolicySetDefinitions lists all built-in policy set definition names using the versionless client,
// then fetches all versioned variants for each using the versioned client.
// We cannot use ListAllBuiltins here because the response exceeds the API size limit.
// If a policy set definition has no versioned variants, the versionless definition is stored instead.
func (c *Cache) fetchPolicySetDefinitions(ctx context.Context, client *armpolicy.ClientFactory, logger *slog.Logger) error {
	setClient := client.NewSetDefinitionsClient()
	pager := setClient.NewListBuiltInPager(nil)

	// Collect all built-in policy set definitions (versionless).
	versionlessDefs := make(map[string]*armpolicy.SetDefinition)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("cache.NewCacheFromAzure: listing built-in policy set definitions: %w", err)
		}

		for _, def := range page.Value {
			if def == nil || def.Name == nil {
				continue
			}

			versionlessDefs[*def.Name] = def
		}
	}

	logger.Info("discovered policy set definitions",
		slog.Int("count", len(versionlessDefs)),
	)

	// Fetch all versioned variants for each policy set definition.
	verClient := client.NewSetDefinitionVersionsClient()

	for name, versionlessDef := range versionlessDefs {
		if err := c.fetchPolicySetDefinitionVersions(ctx, verClient, name, versionlessDef); err != nil {
			return err
		}
	}

	logger.Info("fetched policy set definition versions",
		slog.Int("count", len(c.policySetDefinitions)),
	)

	return nil
}

// fetchPolicySetDefinitionVersions fetches all versioned variants for a specific policy set definition.
// If no versioned variants are found, the versionless definition is stored as a fallback.
func (c *Cache) fetchPolicySetDefinitionVersions(
	ctx context.Context,
	client *armpolicy.SetDefinitionVersionsClient,
	name string,
	versionlessDef *armpolicy.SetDefinition,
) error {
	pager := client.NewListBuiltInPager(name, nil)
	psdvs := assets.NewPolicySetDefinitionVersions()
	hasVersions := false

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf(
				"cache.NewCacheFromAzure: listing built-in policy set definition versions for %s: %w",
				name,
				err,
			)
		}

		for _, v := range page.Value {
			if v == nil {
				continue
			}

			psd, err := assets.NewPolicySetDefinitionFromVersion(*v)
			if err != nil {
				return fmt.Errorf(
					"cache.NewCacheFromAzure: converting built-in policy set definition version for %s: %w",
					name,
					err,
				)
			}

			if err := psdvs.Add(psd, false); err != nil {
				return fmt.Errorf(
					"cache.NewCacheFromAzure: adding built-in policy set definition version for %s: %w",
					name,
					err,
				)
			}

			hasVersions = true
		}
	}

	if !hasVersions && versionlessDef != nil {
		psd := assets.NewPolicySetDefinition(*versionlessDef)

		if err := psdvs.Add(psd, false); err != nil {
			return fmt.Errorf(
				"cache.NewCacheFromAzure: adding versionless built-in policy set definition for %s: %w",
				name,
				err,
			)
		}
	}

	c.policySetDefinitions[name] = psdvs

	return nil
}

// fetchAllHistoricalPolicyDefinitionVersions iterates over every versioned policy
// definition in the cache and fetches all available versions from the per-definition
// pager. The bulk ListAllBuiltins API only returns the latest version per PD, but
// library-defined (custom) policy set definitions may reference older major versions.
// Since we cannot predict which versions will be needed, we fetch all of them.
// Versionless-only definitions (those not available via the versioned API) are skipped.
func (c *Cache) fetchAllHistoricalPolicyDefinitionVersions(ctx context.Context, client *armpolicy.ClientFactory, logger *slog.Logger) error {
	// Collect the names of all versioned PDs (those that came from the versioned API).
	var versionedNames []string
	for name, pdvs := range c.policyDefinitions {
		if len(pdvs.Versions()) > 0 {
			versionedNames = append(versionedNames, name)
		}
	}

	if len(versionedNames) == 0 {
		logger.Info("no versioned policy definitions to fetch historical versions for")
		return nil
	}

	logger.Info("fetching all historical policy definition versions",
		slog.Int("versioned_definitions", len(versionedNames)),
	)

	verClient := client.NewDefinitionVersionsClient()

	for _, name := range versionedNames {
		if err := c.fetchAllPolicyDefinitionVersions(ctx, verClient, name, logger); err != nil {
			return err
		}
	}

	logger.Info("finished fetching historical policy definition versions")

	return nil
}

// fetchAllPolicyDefinitionVersions fetches all available versions for a specific
// policy definition and adds any missing versions to the cache.
func (c *Cache) fetchAllPolicyDefinitionVersions(
	ctx context.Context,
	client *armpolicy.DefinitionVersionsClient,
	name string,
	logger *slog.Logger,
) error {
	pager := client.NewListBuiltInPager(name, nil)

	pdvs, ok := c.policyDefinitions[name]
	if !ok {
		pdvs = assets.NewPolicyDefinitionVersions()
		c.policyDefinitions[name] = pdvs
	}

	added := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf(
				"cache.NewCacheFromAzure: listing all versions for built-in policy definition %s: %w",
				name,
				err,
			)
		}

		for _, v := range page.Value {
			if v == nil {
				continue
			}

			pd, err := assets.NewPolicyDefinitionFromVersion(*v)
			if err != nil {
				return fmt.Errorf(
					"cache.NewCacheFromAzure: converting built-in policy definition version for %s: %w",
					name,
					err,
				)
			}

			// Add with overwrite=false so we don't replace existing entries.
			// Identical duplicates (same version, same content) return nil from Add and are counted.
			// Non-identical duplicates or other errors are real problems.
			if err := pdvs.Add(pd, false); err != nil {
				return fmt.Errorf(
					"cache.NewCacheFromAzure: adding built-in policy definition version for %s: %w",
					name,
					err,
				)
			}
			added++
		}
	}

	logger.Info("fetched all versions for policy definition",
		slog.String("name", name),
		slog.Int("versions_added", added),
		slog.Int("total_versions", len(pdvs.Versions())),
	)

	return nil
}

// discardHandler is a slog.Handler that discards all log records.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }
