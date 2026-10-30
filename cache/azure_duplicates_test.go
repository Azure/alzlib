// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	duplicatesPolicyDefinition      = "2cc2c3b5-c2f8-45aa-a9e6-f90d85ae8352"
	duplicatesOtherPolicyDefinition = "98728c90-32c7-4049-8429-847dc0f4fe37"
	duplicatesPolicySetDefinition   = "e3ec7e09-768c-4b64-882c-fcada3772047"

	gotOnItsOwn = "got on its own"
)

// duplicatesARM fakes the APIs NewCacheFromAzure uses: the bulk listing of the latest policy definition
// versions, the per-definition listing of all versions, the listings of policy set definitions, and the
// GET of a single version, which resolves conflicting duplicates.
type duplicatesARM struct {
	bulk        []*armpolicy.DefinitionVersion
	listed      map[string][]*armpolicy.DefinitionVersion
	setVersions []*armpolicy.SetDefinitionVersion

	// got and setGot answer the GET of a single version, keyed <name>@<version>. Other versions are not found.
	got    map[string]*armpolicy.DefinitionVersion
	setGot map[string]*armpolicy.SetDefinitionVersion
}

func (d duplicatesARM) clientFactory(t *testing.T) *armpolicy.ClientFactory {
	t.Helper()

	srv := fake.ServerFactory{
		DefinitionVersionsServer: fake.DefinitionVersionsServer{
			ListAllBuiltins: func(
				_ context.Context, _ *armpolicy.DefinitionVersionsClientListAllBuiltinsOptions,
			) (resp azfake.Responder[armpolicy.DefinitionVersionsClientListAllBuiltinsResponse], errResp azfake.ErrorResponder) {
				resp.SetResponse(http.StatusOK, armpolicy.DefinitionVersionsClientListAllBuiltinsResponse{
					DefinitionVersionListResult: armpolicy.DefinitionVersionListResult{Value: d.bulk},
				}, nil)

				return resp, errResp
			},
			NewListBuiltInPager: func(
				name string, _ *armpolicy.DefinitionVersionsClientListBuiltInOptions,
			) (resp azfake.PagerResponder[armpolicy.DefinitionVersionsClientListBuiltInResponse]) {
				resp.AddPage(http.StatusOK, armpolicy.DefinitionVersionsClientListBuiltInResponse{
					DefinitionVersionListResult: armpolicy.DefinitionVersionListResult{Value: d.listed[name]},
				}, nil)

				return resp
			},
			GetBuiltIn: func(
				_ context.Context, name, version string, _ *armpolicy.DefinitionVersionsClientGetBuiltInOptions,
			) (resp azfake.Responder[armpolicy.DefinitionVersionsClientGetBuiltInResponse], errResp azfake.ErrorResponder) {
				v, ok := d.got[name+"@"+version]
				if !ok {
					errResp.SetResponseError(http.StatusNotFound, "PolicyDefinitionVersionNotFound")
					return resp, errResp
				}

				resp.SetResponse(http.StatusOK, armpolicy.DefinitionVersionsClientGetBuiltInResponse{DefinitionVersion: *v}, nil)

				return resp, errResp
			},
		},
		DefinitionsServer: fake.DefinitionsServer{
			NewListBuiltInPager: func(
				_ *armpolicy.DefinitionsClientListBuiltInOptions,
			) (resp azfake.PagerResponder[armpolicy.DefinitionsClientListBuiltInResponse]) {
				resp.AddPage(http.StatusOK, armpolicy.DefinitionsClientListBuiltInResponse{}, nil)

				return resp
			},
		},
		SetDefinitionsServer: fake.SetDefinitionsServer{
			NewListBuiltInPager: func(
				_ *armpolicy.SetDefinitionsClientListBuiltInOptions,
			) (resp azfake.PagerResponder[armpolicy.SetDefinitionsClientListBuiltInResponse]) {
				resp.AddPage(http.StatusOK, armpolicy.SetDefinitionsClientListBuiltInResponse{
					SetDefinitionListResult: armpolicy.SetDefinitionListResult{Value: []*armpolicy.SetDefinition{{
						ID:   to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/" + duplicatesPolicySetDefinition),
						Name: to.Ptr(duplicatesPolicySetDefinition),
					}}},
				}, nil)

				return resp
			},
		},
		SetDefinitionVersionsServer: fake.SetDefinitionVersionsServer{
			NewListBuiltInPager: func(
				_ string, _ *armpolicy.SetDefinitionVersionsClientListBuiltInOptions,
			) (resp azfake.PagerResponder[armpolicy.SetDefinitionVersionsClientListBuiltInResponse]) {
				resp.AddPage(http.StatusOK, armpolicy.SetDefinitionVersionsClientListBuiltInResponse{
					SetDefinitionVersionListResult: armpolicy.SetDefinitionVersionListResult{Value: d.setVersions},
				}, nil)

				return resp
			},
			GetBuiltIn: func(
				_ context.Context, name, version string, _ *armpolicy.SetDefinitionVersionsClientGetBuiltInOptions,
			) (resp azfake.Responder[armpolicy.SetDefinitionVersionsClientGetBuiltInResponse], errResp azfake.ErrorResponder) {
				v, ok := d.setGot[name+"@"+version]
				if !ok {
					errResp.SetResponseError(http.StatusNotFound, "PolicySetDefinitionVersionNotFound")
					return resp, errResp
				}

				resp.SetResponse(http.StatusOK, armpolicy.SetDefinitionVersionsClientGetBuiltInResponse{SetDefinitionVersion: *v}, nil)

				return resp, errResp
			},
		},
	}

	cf, err := armpolicy.NewClientFactory("", &azfake.TokenCredential{}, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: fake.NewServerFactoryTransport(&srv)},
	})
	require.NoError(t, err)

	return cf
}

func duplicatesDefinitionVersion(name, version, description string) *armpolicy.DefinitionVersion {
	return &armpolicy.DefinitionVersion{
		ID: to.Ptr(fmt.Sprintf("/providers/Microsoft.Authorization/policyDefinitions/%s/versions/%s", name, version)),
		Properties: &armpolicy.DefinitionVersionProperties{
			Description: to.Ptr(description),
			DisplayName: to.Ptr("unit test policy definition"),
			Mode:        to.Ptr("All"),
			PolicyRule:  map[string]any{},
			Version:     to.Ptr(version),
		},
	}
}

func duplicatesSetDefinitionVersion(version, description string) *armpolicy.SetDefinitionVersion {
	return &armpolicy.SetDefinitionVersion{
		ID: to.Ptr(fmt.Sprintf("/providers/Microsoft.Authorization/policySetDefinitions/%s/versions/%s", duplicatesPolicySetDefinition, version)),
		Properties: &armpolicy.SetDefinitionVersionProperties{
			Description:       to.Ptr(description),
			DisplayName:       to.Ptr("unit test policy set definition"),
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
			Version:           to.Ptr(version),
		},
	}
}

// conflictingListings lists a version twice with different content at each place the cache is filled:
//   - the per-definition listing lists 1.0.1 of duplicatesPolicyDefinition unlike the bulk listing,
//   - the bulk listing lists 1.0.2 of duplicatesOtherPolicyDefinition twice,
//   - the listing of duplicatesPolicySetDefinition lists 1.8.0 twice.
func conflictingListings() duplicatesARM {
	return duplicatesARM{
		bulk: []*armpolicy.DefinitionVersion{
			duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.1", "bulk listing"),
			duplicatesDefinitionVersion(duplicatesOtherPolicyDefinition, "1.0.2", "bulk listing"),
			duplicatesDefinitionVersion(duplicatesOtherPolicyDefinition, "1.0.2", "bulk listing, again and different"),
		},
		listed: map[string][]*armpolicy.DefinitionVersion{
			duplicatesPolicyDefinition: {
				duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.1", "per-definition listing"),
				duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.0", "older version"),
			},
		},
		setVersions: []*armpolicy.SetDefinitionVersion{
			duplicatesSetDefinitionVersion("1.8.0", "listed first"),
			duplicatesSetDefinitionVersion("1.8.0", "listed second"),
		},
	}
}

// newDuplicatesCache creates a cache from azure and returns it with the warnings logged.
func newDuplicatesCache(t *testing.T, azure duplicatesARM) (*Cache, []string) {
	t.Helper()

	var logs bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	c, err := NewCacheFromAzure(t.Context(), azure.clientFactory(t), logger)
	require.NoError(t, err)

	if logs.Len() == 0 {
		return c, nil
	}

	return c, strings.Split(strings.TrimSpace(logs.String()), "\n")
}

// cachedDescriptions returns the descriptions of the versions conflictingListings lists twice.
func cachedDescriptions(t *testing.T, c *Cache) []string {
	t.Helper()

	pd, err := c.PolicyDefinitionVersionsByName(duplicatesPolicyDefinition).GetVersionStrict(to.Ptr("1.0.1"))
	require.NoError(t, err)

	other, err := c.PolicyDefinitionVersionsByName(duplicatesOtherPolicyDefinition).GetVersionStrict(to.Ptr("1.0.2"))
	require.NoError(t, err)

	psd, err := c.PolicySetDefinitionVersionsByName(duplicatesPolicySetDefinition).GetVersionStrict(to.Ptr("1.8.0"))
	require.NoError(t, err)

	return []string{*pd.Properties.Description, *other.Properties.Description, *psd.Properties.Description}
}

// T9: a version listed twice with different content does not fail the cache. The version got on its own
// is stored and each conflict is logged as a warning.
func TestNewCacheFromAzureStoresConflictingVersionGotOnItsOwn(t *testing.T) {
	t.Parallel()

	azure := conflictingListings()
	azure.got = map[string]*armpolicy.DefinitionVersion{
		duplicatesPolicyDefinition + "@1.0.1":      duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.1", gotOnItsOwn),
		duplicatesOtherPolicyDefinition + "@1.0.2": duplicatesDefinitionVersion(duplicatesOtherPolicyDefinition, "1.0.2", gotOnItsOwn),
	}
	azure.setGot = map[string]*armpolicy.SetDefinitionVersion{
		duplicatesPolicySetDefinition + "@1.8.0": duplicatesSetDefinitionVersion("1.8.0", gotOnItsOwn),
	}

	c, warnings := newDuplicatesCache(t, azure)

	assert.Equal(t, []string{gotOnItsOwn, gotOnItsOwn, gotOnItsOwn}, cachedDescriptions(t, c))
	assert.Equal(t, "[1.0.0 1.0.1]", fmt.Sprint(c.PolicyDefinitionVersionsByName(duplicatesPolicyDefinition).Versions()))
	require.Len(t, warnings, 3)

	for _, w := range warnings {
		assert.Contains(t, w, "level=WARN")
		assert.Contains(t, w, "stored the version got on its own")
		assert.Contains(t, w, "already exists and the new definition is different")
	}

	all := strings.Join(warnings, "\n")
	assert.Contains(t, all, "name="+duplicatesPolicyDefinition+" version=1.0.1")
	assert.Contains(t, all, "name="+duplicatesOtherPolicyDefinition+" version=1.0.2")
	assert.Contains(t, all, "name="+duplicatesPolicySetDefinition+" version=1.8.0")
}

// T9: if the version cannot be got on its own, the version listed first is kept.
func TestNewCacheFromAzureKeepsFirstWhenConflictingVersionCannotBeGot(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*duplicatesARM){
		"not found": func(*duplicatesARM) {},
		"another version got": func(d *duplicatesARM) {
			d.got = map[string]*armpolicy.DefinitionVersion{
				duplicatesPolicyDefinition + "@1.0.1":      duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.0", gotOnItsOwn),
				duplicatesOtherPolicyDefinition + "@1.0.2": duplicatesDefinitionVersion(duplicatesOtherPolicyDefinition, "1.0.0", gotOnItsOwn),
			}
			d.setGot = map[string]*armpolicy.SetDefinitionVersion{
				duplicatesPolicySetDefinition + "@1.8.0": duplicatesSetDefinitionVersion("1.7.0", gotOnItsOwn),
			}
		},
	}

	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			azure := conflictingListings()
			setup(&azure)

			c, warnings := newDuplicatesCache(t, azure)

			assert.Equal(t, []string{"bulk listing", "bulk listing", "listed first"}, cachedDescriptions(t, c))
			assert.Equal(t, "[1.0.0 1.0.1]", fmt.Sprint(c.PolicyDefinitionVersionsByName(duplicatesPolicyDefinition).Versions()))
			require.Len(t, warnings, 3)

			for _, w := range warnings {
				assert.Contains(t, w, "level=WARN")
				assert.Contains(t, w, "getting it on its own failed, keeping the version listed first")
			}
		})
	}
}

// Identical duplicates are skipped without getting the version on its own.
func TestNewCacheFromAzureSkipsIdenticalVersions(t *testing.T) {
	t.Parallel()

	azure := duplicatesARM{
		bulk: []*armpolicy.DefinitionVersion{
			duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.1", "listed"),
			duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.1", "listed"),
		},
		listed: map[string][]*armpolicy.DefinitionVersion{
			duplicatesPolicyDefinition: {
				duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.1", "listed"),
				duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.0", "older version"),
			},
		},
		setVersions: []*armpolicy.SetDefinitionVersion{
			duplicatesSetDefinitionVersion("1.8.0", "listed"),
			duplicatesSetDefinitionVersion("1.8.0", "listed"),
		},
	}

	// Getting a version on its own would fail and log a warning.
	c, warnings := newDuplicatesCache(t, azure)
	assert.Empty(t, warnings)
	assert.Equal(t, "[1.0.0 1.0.1]", fmt.Sprint(c.PolicyDefinitionVersionsByName(duplicatesPolicyDefinition).Versions()))
	assert.Equal(t, "[1.8.0]", fmt.Sprint(c.PolicySetDefinitionVersionsByName(duplicatesPolicySetDefinition).Versions()))
}

// Errors other than a conflicting duplicate still fail the cache.
func TestNewCacheFromAzureFailsOnOtherAddErrors(t *testing.T) {
	t.Parallel()

	azure := duplicatesARM{
		bulk: []*armpolicy.DefinitionVersion{
			duplicatesDefinitionVersion(duplicatesPolicyDefinition, "1.0.1", "bulk listing"),
		},
		listed: map[string][]*armpolicy.DefinitionVersion{
			duplicatesPolicyDefinition: {
				duplicatesDefinitionVersion(strings.ToUpper(duplicatesPolicyDefinition), "1.0.0", "another name"),
			},
		},
	}

	_, err := NewCacheFromAzure(t.Context(), azure.clientFactory(t), nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "cannot add with different name than existing version")
}
