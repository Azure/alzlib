// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/alzlib/internal/testutil/fakearm"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeLatency = 20 * time.Millisecond

// newFakeAlzLib returns an AlzLib whose policy client talks to a new fake ARM server.
func newFakeAlzLib(tb testing.TB, parallelism int) (*AlzLib, *fakearm.Server) {
	tb.Helper()

	srv := fakearm.New()
	cf, err := srv.NewClientFactory()
	require.NoError(tb, err)

	az := NewAlzLib(&Options{
		Parallelism:           parallelism,
		AllowOverwrite:        false,
		UniqueRoleDefinitions: true,
	})
	az.AddPolicyClient(cf)

	return az, srv
}

func policyDefinitionRequest(tb testing.TB, name string, version *string) BuiltInRequest {
	tb.Helper()

	resID, err := arm.ParseResourceID(fmt.Sprintf("/providers/Microsoft.Authorization/policyDefinitions/%s", name))
	require.NoError(tb, err)

	return BuiltInRequest{ResourceID: resID, Version: version}
}

func policySetDefinitionRequest(tb testing.TB, name string) BuiltInRequest {
	tb.Helper()

	resID, err := arm.ParseResourceID(fmt.Sprintf("/providers/Microsoft.Authorization/policySetDefinitions/%s", name))
	require.NoError(tb, err)

	return BuiltInRequest{ResourceID: resID}
}

// addFakePolicyDefinitions registers count policy definitions named pd-NNN and returns versionless
// requests for them.
func addFakePolicyDefinitions(tb testing.TB, srv *fakearm.Server, count int) []BuiltInRequest {
	tb.Helper()

	reqs := make([]BuiltInRequest, 0, count)

	for i := range count {
		name := fmt.Sprintf("pd-%03d", i)
		srv.AddPolicyDefinition(name, "1.0.0")
		reqs = append(reqs, policyDefinitionRequest(tb, name, nil))
	}

	return reqs
}

func TestGetDefinitionsFromAzureRespectsParallelism(t *testing.T) {
	t.Parallel()

	for _, p := range []int{1, 4, 10} {
		t.Run(fmt.Sprintf("parallelism-%d", p), func(t *testing.T) {
			t.Parallel()

			az, srv := newFakeAlzLib(t, p)
			srv.Latency = fakeLatency
			reqs := addFakePolicyDefinitions(t, srv, 40)

			require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

			for _, req := range reqs {
				assert.True(t, az.PolicyDefinitionExists(req.ResourceID.Name, nil), req.ResourceID.Name)
				assert.Equal(t, 1, srv.Calls(req.ResourceID.Name), req.ResourceID.Name)
			}

			assert.LessOrEqual(t, srv.PeakInFlight(), p)

			if p == 1 {
				assert.Equal(t, 1, srv.PeakInFlight())
			} else {
				assert.Greater(t, srv.PeakInFlight(), 1)
			}
		})
	}
}

func TestGetDefinitionsFromAzureReferencedDefinitionsFetchedConcurrently(t *testing.T) {
	t.Parallel()

	const parallelism = 8

	az, srv := newFakeAlzLib(t, parallelism)
	srv.Latency = fakeLatency

	refs := make([]fakearm.Reference, 0, 30)

	for i := range 30 {
		name := fmt.Sprintf("ref-pd-%03d", i)
		srv.AddPolicyDefinition(name, "1.0.0", "1.1.0")

		var version *string
		if i%2 == 0 {
			version = to.Ptr("1.*.*")
		}

		refs = append(refs, fakearm.Reference{Name: name, Version: version})
	}

	srv.AddPolicySetDefinition("psd", []string{"1.0.0"}, refs...)

	reqs := []BuiltInRequest{policySetDefinitionRequest(t, "psd")}
	require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

	require.True(t, az.PolicySetDefinitionExists("psd", nil))

	for _, ref := range refs {
		assert.True(t, az.PolicyDefinitionExists(ref.Name, ref.Version), ref.Name)
		assert.Equal(t, 1, srv.Calls(ref.Name), ref.Name)
	}

	assert.Greater(t, srv.PeakInFlight(), 1)
	assert.LessOrEqual(t, srv.PeakInFlight(), parallelism)
}

func TestGetDefinitionsFromAzureSharedDefinitionsFetchedOnce(t *testing.T) {
	t.Parallel()

	az, srv := newFakeAlzLib(t, 10)
	srv.Latency = fakeLatency

	shared := []string{"shared-a", "shared-b", "shared-c"}
	for _, name := range shared {
		srv.AddPolicyDefinition(name, "1.0.0")
	}

	srv.AddPolicyDefinition("direct-dup", "1.0.0")
	srv.AddPolicySetDefinition("psd-1", []string{"1.0.0"},
		fakearm.Reference{Name: "shared-a"},
		fakearm.Reference{Name: "shared-b", Version: to.Ptr("1.*.*")},
		fakearm.Reference{Name: "shared-c"},
	)
	srv.AddPolicySetDefinition("psd-2", []string{"1.0.0"},
		fakearm.Reference{Name: "shared-a", Version: to.Ptr("1.*.*")},
		fakearm.Reference{Name: "shared-b"},
		fakearm.Reference{Name: "shared-c", Version: to.Ptr("1.0.*")},
	)

	reqs := []BuiltInRequest{
		policyDefinitionRequest(t, "direct-dup", nil),
		policyDefinitionRequest(t, "direct-dup", nil),
		policyDefinitionRequest(t, "direct-dup", to.Ptr("1.*.*")),
		policySetDefinitionRequest(t, "psd-1"),
		policySetDefinitionRequest(t, "psd-2"),
		policySetDefinitionRequest(t, "psd-1"),
	}

	require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

	for _, name := range append(shared, "direct-dup", "psd-1", "psd-2") {
		assert.Equal(t, 1, srv.Calls(name), name)
	}
}

func TestGetDefinitionsFromAzureConcurrentCallers(t *testing.T) {
	t.Parallel()

	const callers = 4

	az, srv := newFakeAlzLib(t, 10)
	srv.Latency = fakeLatency
	reqs := addFakePolicyDefinitions(t, srv, 20)

	var wg sync.WaitGroup

	errs := make([]error, callers)

	for i := range callers {
		wg.Go(func() {
			errs[i] = az.GetDefinitionsFromAzure(t.Context(), reqs)
		})
	}

	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}

	for _, req := range reqs {
		assert.Equal(t, 1, srv.Calls(req.ResourceID.Name), req.ResourceID.Name)
	}
}

func TestGetDefinitionsFromAzureFirstErrorCancelsRemainingWork(t *testing.T) {
	t.Parallel()

	const count = 50

	az, srv := newFakeAlzLib(t, 4)
	srv.Latency = fakeLatency
	reqs := addFakePolicyDefinitions(t, srv, count)
	srv.FailDefinition(reqs[0].ResourceID.Name, http.StatusNotFound)

	err := az.GetDefinitionsFromAzure(t.Context(), reqs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), reqs[0].ResourceID.Name)
	assert.Less(t, srv.TotalCalls(), count)
	assert.Equal(t, 1, srv.Calls(reqs[0].ResourceID.Name), "errors other than HTTP 429 must not be retried")
}

func TestGetDefinitionsFromAzureRetriesThrottledRequests(t *testing.T) {
	t.Parallel()

	// The fake client factory disables the Azure SDK's own retries, so every retry here is alzlib's.
	az, srv := newFakeAlzLib(t, 10)
	reqs := addFakePolicyDefinitions(t, srv, 20)

	for _, req := range reqs {
		srv.ThrottleDefinition(req.ResourceID.Name, 2, "0")
	}

	srv.AddPolicyDefinition("ref-versioned", "1.0.0", "1.1.0")
	srv.AddPolicyDefinition("ref-latest", "1.0.0")
	srv.AddPolicySetDefinition("psd", []string{"1.0.0"},
		fakearm.Reference{Name: "ref-versioned", Version: to.Ptr("1.*.*")},
		fakearm.Reference{Name: "ref-latest"},
	)

	for _, name := range []string{"psd", "ref-versioned", "ref-latest"} {
		srv.ThrottleDefinition(name, maxThrottleRetries, "0")
	}

	reqs = append(reqs, policySetDefinitionRequest(t, "psd"))

	require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

	for _, req := range reqs[:20] {
		assert.True(t, az.PolicyDefinitionExists(req.ResourceID.Name, nil), req.ResourceID.Name)
		assert.Equal(t, 3, srv.Calls(req.ResourceID.Name), req.ResourceID.Name)
	}

	assert.True(t, az.PolicySetDefinitionExists("psd", nil))
	assert.True(t, az.PolicyDefinitionExists("ref-versioned", to.Ptr("1.*.*")))
	assert.True(t, az.PolicyDefinitionExists("ref-latest", nil))

	for _, name := range []string{"psd", "ref-versioned", "ref-latest"} {
		assert.Equal(t, maxThrottleRetries+1, srv.Calls(name), name)
	}
}

func TestGetDefinitionsFromAzureGivesUpWhenThrottlingPersists(t *testing.T) {
	t.Parallel()

	az, srv := newFakeAlzLib(t, 4)
	reqs := addFakePolicyDefinitions(t, srv, 1)
	srv.ThrottleDefinition(reqs[0].ResourceID.Name, -1, "0")

	err := az.GetDefinitionsFromAzure(t.Context(), reqs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "429")
	assert.Equal(t, maxThrottleRetries+1, srv.Calls(reqs[0].ResourceID.Name))
}

func TestGetDefinitionsFromAzureThrottleWaitHonoursCancellation(t *testing.T) {
	t.Parallel()

	az, srv := newFakeAlzLib(t, 4)
	reqs := addFakePolicyDefinitions(t, srv, 1)
	srv.ThrottleDefinition(reqs[0].ResourceID.Name, -1, "30")

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := az.GetDefinitionsFromAzure(ctx, reqs)

	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, 1, srv.Calls(reqs[0].ResourceID.Name))
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header http.Header
		want   time.Duration
		ok     bool
	}{
		{name: "none", header: http.Header{}, ok: false},
		{name: "seconds", header: http.Header{"Retry-After": {"7"}}, want: 7 * time.Second, ok: true},
		{name: "zero", header: http.Header{"Retry-After": {"0"}}, want: 0, ok: true},
		{name: "retry-after-ms", header: http.Header{"Retry-After-Ms": {"250"}}, want: 250 * time.Millisecond, ok: true},
		{name: "x-ms-retry-after-ms", header: http.Header{"X-Ms-Retry-After-Ms": {"1500"}}, want: 1500 * time.Millisecond, ok: true},
		{
			name:   "milliseconds take precedence",
			header: http.Header{"Retry-After": {"9"}, "Retry-After-Ms": {"100"}},
			want:   100 * time.Millisecond,
			ok:     true,
		},
		{name: "past date", header: http.Header{"Retry-After": {"Mon, 02 Jan 2006 15:04:05 GMT"}}, want: 0, ok: true},
		{name: "invalid", header: http.Header{"Retry-After": {"soon"}}, ok: false},
		{name: "negative", header: http.Header{"Retry-After": {"-1"}}, ok: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := retryAfter(tc.header)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestThrottleDelayBackoffWithoutRetryAfter(t *testing.T) {
	t.Parallel()

	for attempt := range maxThrottleRetries + 1 {
		backoff := min(throttleBaseDelay<<attempt, throttleMaxDelay)
		got := throttleDelay(errors.New("not a response error"), attempt)

		assert.GreaterOrEqual(t, got, backoff/2, "attempt %d", attempt)
		assert.LessOrEqual(t, got, backoff, "attempt %d", attempt)
	}
}

func TestGetDefinitionsFromAzureHonoursCallerCancellation(t *testing.T) {
	t.Parallel()

	az, srv := newFakeAlzLib(t, 4)
	srv.Latency = time.Second
	reqs := addFakePolicyDefinitions(t, srv, 20)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := az.GetDefinitionsFromAzure(ctx, reqs)

	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestGetDefinitionsFromAzureMissingReferencedVersionReportsAvailableVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		versions []string
		want     string
	}{
		{name: "other versions available", versions: []string{"1.0.0"}, want: "Versions available: [1.0.0]"},
		{name: "no versions available", versions: nil, want: "Versions available: []"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az, srv := newFakeAlzLib(t, 10)
			srv.AddPolicyDefinition("pd-missing-version", tc.versions...)
			srv.AddPolicySetDefinition("psd", []string{"1.0.0"},
				fakearm.Reference{Name: "pd-missing-version", Version: to.Ptr("2.*.*")},
			)

			err := az.GetDefinitionsFromAzure(t.Context(), []BuiltInRequest{policySetDefinitionRequest(t, "psd")})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestEffectiveParallelism(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts *Options
		want int
	}{
		{name: "nil options", opts: nil, want: 1},
		{name: "zero", opts: &Options{Parallelism: 0}, want: 1},
		{name: "negative", opts: &Options{Parallelism: -3}, want: 1},
		{name: "positive", opts: &Options{Parallelism: 7}, want: 7},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az := &AlzLib{Options: tc.opts}
			assert.Equal(t, tc.want, az.effectiveParallelism())
		})
	}
}

func TestGroupByNameIsCaseInsensitiveAndOrdered(t *testing.T) {
	t.Parallel()

	items := []string{"b", "A", "c", "a", "B", "b"}
	groups := groupByName(items, strings.Clone)

	assert.Equal(t, [][]string{{"b", "B", "b"}, {"A", "a"}, {"c"}}, groups)
	assert.Empty(t, groupByName([]string{}, strings.Clone))
}

// BenchmarkGetDefinitionsFromAzureSimulatedLatency measures fetching 100 policy definitions with
// 10ms of simulated latency per request, at different levels of parallelism.
func BenchmarkGetDefinitionsFromAzureSimulatedLatency(b *testing.B) {
	for _, p := range []int{1, 10} {
		b.Run(fmt.Sprintf("parallelism-%d", p), func(b *testing.B) {
			for b.Loop() {
				b.StopTimer()

				az, srv := newFakeAlzLib(b, p)
				srv.Latency = 10 * time.Millisecond
				reqs := addFakePolicyDefinitions(b, srv, 100)

				b.StartTimer()

				if err := az.GetDefinitionsFromAzure(b.Context(), reqs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
