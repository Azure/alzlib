// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"golang.org/x/sync/errgroup"
)

const (
	// maxThrottleRetries is the number of times a definition is fetched again after Azure Resource
	// Manager throttled it (HTTP 429) beyond the retries of the Azure SDK.
	maxThrottleRetries = 5
	// throttleBaseDelay is the first back-off delay when a throttled response has no Retry-After.
	throttleBaseDelay = 2 * time.Second
	// throttleMaxDelay caps every back-off delay, including a requested Retry-After.
	throttleMaxDelay = 60 * time.Second
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
// An item throttled by Azure Resource Manager is retried, see withThrottleRetry.
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

				if err := withThrottleRetry(grpCtx, func() error { return fn(grpCtx, item) }); err != nil {
					return err
				}
			}

			return nil
		})
	}

	return grp.Wait()
}

// withThrottleRetry calls fn and, while it fails because Azure Resource Manager throttled a request
// (HTTP 429), waits and calls it again, up to maxThrottleRetries times.
// The Azure SDK already retries throttled requests, but only a few times. Concurrent fetching, and
// several processes sharing a tenant, can exhaust those retries, so a throttled definition is
// fetched again after the delay requested by Retry-After, or an exponential back-off.
// fn must be safe to call again after a failure: the fetch functions first check whether the
// definition already exists.
func withThrottleRetry(ctx context.Context, fn func() error) error {
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil || attempt == maxThrottleRetries || !isThrottled(err) {
			return err
		}

		timer := time.NewTimer(throttleDelay(err, attempt))

		select {
		case <-ctx.Done():
			timer.Stop()

			return err
		case <-timer.C:
		}
	}
}

// isThrottled reports whether err is an Azure Resource Manager HTTP 429 response.
func isThrottled(err error) bool {
	var respErr *azcore.ResponseError

	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusTooManyRequests
}

// throttleDelay returns how long to wait before retrying after a throttled response: the delay
// requested by the response, or an exponential back-off with jitter, capped at throttleMaxDelay.
func throttleDelay(err error, attempt int) time.Duration {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) && respErr.RawResponse != nil {
		if d, ok := retryAfter(respErr.RawResponse.Header); ok {
			return min(d, throttleMaxDelay)
		}
	}

	backoff := min(throttleBaseDelay<<attempt, throttleMaxDelay)

	return backoff/2 + rand.N(backoff/2+1)
}

// retryAfter parses the delay requested by a throttled response, from the retry-after-ms,
// x-ms-retry-after-ms or Retry-After (seconds or HTTP date) header.
func retryAfter(h http.Header) (time.Duration, bool) {
	for _, name := range []string{"retry-after-ms", "x-ms-retry-after-ms"} {
		if v := h.Get(name); v != "" {
			if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
				return time.Duration(ms) * time.Millisecond, true
			}
		}
	}

	v := h.Get("Retry-After")
	if v == "" {
		return 0, false
	}

	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second, true
	}

	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0), true
	}

	return 0, false
}
