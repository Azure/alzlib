// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/Azure/alzlib/cache"
	"github.com/Azure/alzlib/internal/testutil/fakearm"
	"github.com/Azure/alzlib/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBulkTestAlzLib returns an AlzLib whose policy client talks to srv. The client is added with
// AddPolicyClientFromCredential if bulk is set, and with AddPolicyClient otherwise.
func newBulkTestAlzLib(tb testing.TB, srv *fakearm.Server, bulk bool) *AlzLib {
	tb.Helper()

	az := NewAlzLib(&Options{Parallelism: 10, UniqueRoleDefinitions: true})

	if bulk {
		require.NoError(tb, az.AddPolicyClientFromCredential(srv.Credential(), srv.ClientOptions()))

		return az
	}

	cf, err := srv.NewClientFactory()
	require.NoError(tb, err)
	az.AddPolicyClient(cf)

	return az
}

// bulkTestCache returns a cache holding version 1.1.0 of each named built-in policy definition, fetched
// from a fake ARM server with versions 1.0.0, 1.1.0 and 2.0.0.
func bulkTestCache(t *testing.T, names ...string) *cache.Cache {
	t.Helper()

	srv := fakearm.New()
	reqs := make([]BuiltInRequest, 0, len(names))

	for _, name := range names {
		srv.AddPolicyDefinition(name, "1.0.0", "1.1.0", "2.0.0")
		reqs = append(reqs, policyDefinitionRequest(t, name, to.Ptr("1.*.*")))
	}

	az := newBulkTestAlzLib(t, srv, false)
	require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

	return az.ExportBuiltInCache()
}

// bulkTestServer returns a fake ARM server and requests that list the versions of more than
// minBulkListedDefinitions definitions: with stable, preview and deprecated constraints, directly and
// through a policy set definition, and for one definition with different constraints both ways.
func bulkTestServer(t *testing.T) (*fakearm.Server, []BuiltInRequest) {
	t.Helper()

	srv := fakearm.New()
	srv.AddPolicyDefinition("pd-stable", "1.0.0", "1.1.0", "2.0.0")
	srv.AddPolicyDefinition("pd-preview", "1.0.0", "1.1.0-preview", "1.2.0-preview", "2.0.0-preview")
	srv.AddPolicyDefinition("pd-deprecated", "1.0.0-deprecated", "1.1.0")
	srv.AddPolicyDefinition("pd-exact", "1.0.0", "1.0.1")
	srv.AddPolicyDefinition("pd-shared", "1.0.0", "1.1.0-preview", "2.0.0")
	srv.AddPolicyDefinition("pd-case", "1.0.0")
	srv.AddPolicyDefinition("pd-cached", "1.0.0", "1.1.0", "2.0.0")
	srv.AddPolicyDefinition("pd-latest", "1.0.0", "1.1.0")
	srv.AddPolicyDefinition("pd-ref-latest", "1.0.0")
	srv.AddPolicyDefinition("pd-unrequested", "1.0.0")
	srv.AddPolicySetDefinition("psd", []string{"1.0.0"},
		fakearm.Reference{Name: "pd-deprecated", Version: to.Ptr("1.*.*-deprecated")},
		fakearm.Reference{Name: "pd-shared", Version: to.Ptr("1.*.*-preview")},
		fakearm.Reference{Name: "pd-preview", Version: to.Ptr("2.*.*-preview")},
		fakearm.Reference{Name: "pd-cached", Version: to.Ptr("2.*.*")},
		fakearm.Reference{Name: "pd-ref-latest"},
	)

	reqs := []BuiltInRequest{
		policyDefinitionRequest(t, "pd-stable", to.Ptr("1.*.*")),
		policyDefinitionRequest(t, "pd-preview", to.Ptr("1.*.*-preview")),
		policyDefinitionRequest(t, "pd-exact", to.Ptr("1.0.0")),
		policyDefinitionRequest(t, "pd-shared", to.Ptr("2.*.*")),
		policyDefinitionRequest(t, "PD-Case", to.Ptr("1.*.*")),
		policyDefinitionRequest(t, "pd-cached", to.Ptr("1.*.*")),
		policyDefinitionRequest(t, "pd-latest", nil),
		policySetDefinitionRequest(t, "psd"),
	}

	for i := range minBulkListedDefinitions {
		name := fmt.Sprintf("pd-filler-%02d", i)
		srv.AddPolicyDefinition(name, "1.0.0", "1.1.0")
		reqs = append(reqs, policyDefinitionRequest(t, name, to.Ptr("1.*.*")))
	}

	return srv, reqs
}

// unversionedCalls are the requests made with the bulk listing for the requests of bulkTestServer: for the
// definitions requested without a version.
func unversionedCalls() map[string]int {
	return map[string]int{"pd-latest": 1, "pd-ref-latest": 1, "psd": 1}
}

func TestGetDefinitionsFromAzureBulkListingAddsTheSameDefinitions(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, bulk bool) (*AlzLib, *fakearm.Server) {
		t.Helper()

		srv, reqs := bulkTestServer(t)
		az := newBulkTestAlzLib(t, srv, bulk)
		az.AddCache(bulkTestCache(t, "pd-cached"))
		require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

		return az, srv
	}

	off, offSrv := run(t, false)
	on, onSrv := run(t, true)

	assert.Equal(t, off.policyDefinitions, on.policyDefinitions)
	assert.Equal(t, off.policySetDefinitions, on.policySetDefinitions)
	assert.Contains(t, on.policyDefinitions, "PD-Case", "definitions are stored under the requested name")

	assert.Zero(t, offSrv.BulkVersionListingCalls())
	assert.Zero(t, offSrv.DefinitionListingCalls())
	assert.Equal(t, 1, onSrv.BulkVersionListingCalls())
	assert.Equal(t, 1, onSrv.DefinitionListingCalls())
	assert.Equal(t, unversionedCalls(), onSrv.AllCalls(), "only definitions without a version are requested on their own")
}

func TestGetDefinitionsFromAzureBulkListingLeavesOutVersionsThatDoNotExist(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, bulk bool) (*AlzLib, *fakearm.Server) {
		t.Helper()

		srv, reqs := bulkTestServer(t)
		srv.AddPolicyDefinition("pd-phantom", "1.0.1", "1.0.2")
		srv.AddPolicyDefinition("pd-phantom-ref", "1.0.1")
		srv.AddPolicySetDefinition("psd-phantom", []string{"1.0.0"},
			fakearm.Reference{Name: "pd-phantom-ref", Version: to.Ptr("1.*.*")},
		)
		// Azure lists these versions in bulk, but they do not exist. 1.0.0-preview is what 1.*.*-preview
		// would resolve to, instead of 1.0.2.
		srv.AddPhantomPolicyDefinitionVersion("pd-phantom", "1.0.0-preview")
		srv.AddPhantomPolicyDefinitionVersion("pd-phantom-ref", "1.0.0")

		reqs = append(reqs,
			policyDefinitionRequest(t, "pd-phantom", to.Ptr("1.*.*-preview")),
			policySetDefinitionRequest(t, "psd-phantom"),
		)

		az := newBulkTestAlzLib(t, srv, bulk)
		require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

		return az, srv
	}

	off, _ := run(t, false)
	on, onSrv := run(t, true)

	assert.Zero(t, onSrv.Calls("pd-phantom"), "the versions should come from the bulk listing")
	assert.Zero(t, onSrv.Calls("pd-phantom-ref"), "the versions should come from the bulk listing")
	assert.Equal(t, off.policyDefinitions, on.policyDefinitions)

	pd := on.PolicyDefinition("pd-phantom", to.Ptr("1.*.*-preview"))
	require.NotNil(t, pd)
	assert.Equal(t, "1.0.2", *pd.Properties.Version)
	assert.Equal(t, "[1.0.1]", on.policyDefinitionVersionsString("pd-phantom-ref"))
}

func TestGetDefinitionsFromAzureBulkListingFallsBackToListingEachDefinition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(t *testing.T, srv *fakearm.Server)
		// listedAlone are the definitions whose versions are listed on their own, as without the bulk
		// listing. Nil means all of them.
		listedAlone []string
	}{
		{
			name: "a page fails",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				srv.SetListPageSize(5)
				srv.FailBulkVersionListing(1, http.StatusInternalServerError, "InternalServerError")
			},
		},
		{
			name: "the response is too large",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				srv.FailBulkVersionListing(0, http.StatusBadRequest, "ResponseTooLarge")
			},
		},
		{
			name: "throttled",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				srv.FailBulkVersionListing(0, http.StatusTooManyRequests, "TooManyRequests")
			},
		},
		{
			name: "listing the definitions fails",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				srv.FailDefinitionListing(0, http.StatusInternalServerError, "InternalServerError")
			},
		},
		{
			name: "too many pages of versions",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				for i := range maxBulkListingPages {
					srv.AddPhantomPolicyDefinitionVersion("pd-unrequested", fmt.Sprintf("0.0.%d", i))
				}

				srv.SetListPageSize(1)
			},
		},
		{
			name: "too many pages of definitions",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				for i := range maxBulkListingPages {
					srv.AddPolicyDefinition(fmt.Sprintf("pd-versionless-%02d", i))
				}

				srv.SetListPageSize(1)
			},
		},
		{
			name: "a definition is not in the bulk listing",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				srv.OmitFromBulkVersionListing("pd-stable")
			},
			listedAlone: []string{"pd-stable"},
		},
		{
			name: "a version is not in the bulk listing",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				srv.OmitFromBulkVersionListing("pd-shared", "1.1.0-preview")
			},
			listedAlone: []string{"pd-shared"},
		},
		{
			name: "a version is listed twice with different content",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				srv.ListTwiceInBulkVersionListing("pd-shared", "2.0.0")
			},
			listedAlone: []string{"pd-shared"},
		},
		{
			name: "a definition is listed twice",
			configure: func(_ *testing.T, srv *fakearm.Server) {
				srv.ListTwiceInDefinitionListing("pd-shared", "2.0.0")
			},
			listedAlone: []string{"pd-shared"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			offSrv, reqs := bulkTestServer(t)
			off := newBulkTestAlzLib(t, offSrv, false)
			require.NoError(t, off.GetDefinitionsFromAzure(t.Context(), reqs))

			onSrv, reqs := bulkTestServer(t)
			tc.configure(t, onSrv)
			on := newBulkTestAlzLib(t, onSrv, true)
			require.NoError(t, on.GetDefinitionsFromAzure(t.Context(), reqs))

			want := offSrv.AllCalls()
			if tc.listedAlone != nil {
				want = unversionedCalls()
				for _, name := range tc.listedAlone {
					want[name] = offSrv.Calls(name)
				}
			}

			assert.Equal(t, want, onSrv.AllCalls())
			assert.Equal(t, off.policyDefinitions, on.policyDefinitions)
			assert.Equal(t, off.policySetDefinitions, on.policySetDefinitions)
		})
	}
}

func TestGetDefinitionsFromAzureBulkListingDoesNotFollowNextLinksElsewhere(t *testing.T) {
	t.Parallel()

	for _, base := range []string{"https://example.com", "http://management.azure.com"} {
		t.Run(base, func(t *testing.T) {
			t.Parallel()

			srv, reqs := bulkTestServer(t)
			srv.SetListPageSize(5)
			require.NoError(t, srv.SetBulkVersionListingNextLinkBase(base))

			az := newBulkTestAlzLib(t, srv, true)
			require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

			assert.Equal(t, 1, srv.BulkVersionListingCalls(), "the nextLink must not be requested")
			assert.Equal(t, 1, srv.Calls("pd-stable"), "the versions should be listed on their own")
		})
	}
}

func TestCheckNextLink(t *testing.T) {
	t.Parallel()

	endpoint, err := url.Parse("https://management.azure.com/")
	require.NoError(t, err)

	tests := []struct {
		link string
		ok   bool
	}{
		{link: "https://management.azure.com/providers/x?$skiptoken=1", ok: true},
		{link: "https://MANAGEMENT.AZURE.COM/providers/x", ok: true},
		{link: "http://management.azure.com/providers/x"},
		{link: "https://example.com/providers/x"},
		{link: "https://management.azure.com.example.com/providers/x"},
		{link: "https://management.azure.com:8443/providers/x"},
		{link: "/providers/x"},
		{link: "https://management.azure.com/%zz"},
	}

	for _, tc := range tests {
		t.Run(tc.link, func(t *testing.T) {
			t.Parallel()

			err := checkNextLink(endpoint, tc.link)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestGetDefinitionsFromAzureWithoutBulkListing(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, addClient func(az *AlzLib, srv *fakearm.Server)) *fakearm.Server {
		t.Helper()

		srv, reqs := bulkTestServer(t)
		az := NewAlzLib(nil)
		addClient(az, srv)
		require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

		assert.Zero(t, srv.BulkVersionListingCalls())
		assert.Zero(t, srv.DefinitionListingCalls())

		return srv
	}

	addPolicyClient := func(az *AlzLib, srv *fakearm.Server) {
		cf, err := srv.NewClientFactory()
		require.NoError(t, err)
		az.AddPolicyClient(cf)
	}

	baseline := run(t, addPolicyClient)
	replaced := run(t, func(az *AlzLib, srv *fakearm.Server) {
		require.NoError(t, az.AddPolicyClientFromCredential(srv.Credential(), srv.ClientOptions()))
		addPolicyClient(az, srv)
	})

	assert.Equal(t, baseline.AllCalls(), replaced.AllCalls())
}

func TestGetDefinitionsFromAzureBulkListingThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// listed and cached are the numbers of definitions requested with a version that is listed from
		// Azure, or found in the cache.
		listed, cached int
		// referenced requests the listed definitions through a policy set definition.
		referenced bool
		wantBulk   bool
	}{
		{name: "too few to list", listed: minBulkListedDefinitions - 1, cached: 2},
		{name: "enough to list", listed: minBulkListedDefinitions, wantBulk: true},
		{name: "enough referenced to list", listed: minBulkListedDefinitions, referenced: true, wantBulk: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := fakearm.New()
			reqs := make([]BuiltInRequest, 0, tc.listed+tc.cached+1)
			refs := make([]fakearm.Reference, 0, tc.listed)
			cached := make([]string, 0, tc.cached)

			for i := range tc.listed {
				name := fmt.Sprintf("pd-listed-%02d", i)
				srv.AddPolicyDefinition(name, "1.0.0", "1.1.0")

				if tc.referenced {
					refs = append(refs, fakearm.Reference{Name: name, Version: to.Ptr("1.*.*")})
				} else {
					reqs = append(reqs, policyDefinitionRequest(t, name, to.Ptr("1.*.*")))
				}
			}

			for i := range tc.cached {
				name := fmt.Sprintf("pd-cached-%02d", i)
				cached = append(cached, name)
				reqs = append(reqs, policyDefinitionRequest(t, name, to.Ptr("1.*.*")))
			}

			if tc.referenced {
				srv.AddPolicySetDefinition("psd", []string{"1.0.0"}, refs...)

				reqs = append(reqs, policySetDefinitionRequest(t, "psd"))
			}

			az := newBulkTestAlzLib(t, srv, true)
			az.AddCache(bulkTestCache(t, cached...))
			require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), reqs))

			wantBulkCalls, wantListingCalls := 0, 1
			if tc.wantBulk {
				wantBulkCalls, wantListingCalls = 1, 0
			}

			assert.Equal(t, wantBulkCalls, srv.BulkVersionListingCalls())
			assert.Equal(t, wantBulkCalls, srv.DefinitionListingCalls())

			for i := range tc.listed {
				name := fmt.Sprintf("pd-listed-%02d", i)
				assert.True(t, az.PolicyDefinitionExists(name, to.Ptr("1.1.0")), name)
				assert.Equal(t, wantListingCalls, srv.Calls(name), name)
			}
		})
	}
}
