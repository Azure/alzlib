// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"golang.org/x/sync/errgroup"
)

// definitionReference is a validated policy definition reference from a built-in policy set definition.
type definitionReference struct {
	setDefinition *assets.PolicySetDefinition
	ref           *armpolicy.DefinitionReference
	resID         *arm.ResourceID
}

// effectiveParallelism returns the maximum number of concurrent Azure API calls used when fetching
// built-in definitions. Values below 1 fall back to serial fetching.
func (az *AlzLib) effectiveParallelism() int {
	if az.Options == nil || az.Options.Parallelism < 1 {
		return 1
	}

	return az.Options.Parallelism
}

// policyClientFactory returns the policy client factory, or nil if it has not been set.
func (az *AlzLib) policyClientFactory() *armpolicy.ClientFactory {
	az.mu.RLock()
	defer az.mu.RUnlock()

	return az.clients.policyClient
}

// policyDefinitionVersionsString returns the stored versions of the named policy definition for use in
// error messages.
func (az *AlzLib) policyDefinitionVersionsString(name string) string {
	az.mu.RLock()
	defer az.mu.RUnlock()

	pdvs, ok := az.policyDefinitions[name]
	if !ok || pdvs == nil {
		return "[]"
	}

	return fmt.Sprint(pdvs.Versions())
}

// parseDefinitionReference validates a policy definition reference of the supplied policy set definition.
// It returns nil if the reference is nil, as there is nothing to fetch.
func parseDefinitionReference(
	setDefinition *assets.PolicySetDefinition,
	ref *armpolicy.DefinitionReference,
) (*definitionReference, error) {
	if ref == nil {
		return nil, nil
	}

	if ref.PolicyDefinitionID == nil {
		return nil, fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error getting policy definition references for policy set definition `%s`: "+
				"policy definition ID is nil",
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
		)
	}

	resID, err := arm.ParseResourceID(*ref.PolicyDefinitionID)
	if err != nil {
		return nil, fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error parsing resource id `%s` referenced in policy set `%s`",
			*ref.PolicyDefinitionID,
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
		)
	}

	return &definitionReference{
		setDefinition: setDefinition,
		ref:           ref,
		resID:         resID,
	}, nil
}

// groupByName groups items by case-insensitive definition name, preserving first-seen order.
// Items in one group are processed serially, so two requests for the same definition can never race
// to add it, while different definitions are fetched concurrently.
func groupByName[T any](items []T, name func(T) string) [][]T {
	groups := make([][]T, 0, len(items))
	index := make(map[string]int, len(items))

	for _, item := range items {
		key := strings.ToLower(name(item))

		if i, ok := index[key]; ok {
			groups[i] = append(groups[i], item)
			continue
		}

		index[key] = len(groups)
		groups = append(groups, []T{item})
	}

	return groups
}

// forEachGroupConcurrently calls fn for every item, running at most limit groups at once.
// Items within a group are processed in order.
// The first error cancels the remaining work and is returned.
func forEachGroupConcurrently[T any](
	ctx context.Context,
	limit int,
	groups [][]T,
	fn func(context.Context, T) error,
) error {
	if len(groups) == 0 {
		return nil
	}

	grp, grpCtx := errgroup.WithContext(ctx)
	grp.SetLimit(max(limit, 1))

	for _, group := range groups {
		grp.Go(func() error {
			for _, item := range group {
				if err := grpCtx.Err(); err != nil {
					return err
				}

				if err := fn(grpCtx, item); err != nil {
					return err
				}
			}

			return nil
		})
	}

	return grp.Wait()
}
