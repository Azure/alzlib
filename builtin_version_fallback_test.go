// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file cover the fallback for an incomplete built-in version listing,
// Azure/Azure-Landing-Zones#4327. A definition is requested through one of the three paths that list
// versions:
//
//   - direct: a policy definition requested with a version constraint (Alzlib.addVersionedPolicyDefinition),
//   - referenced: a policy definition referenced with a version constraint by a built-in policy set
//     (Alzlib.fetchReferencedPolicyDefinitionVersions),
//   - set: a policy set definition requested with a version constraint (Alzlib.addVersionedPolicySetDefinition).
const (
	fallbackPathDirect     = "direct"
	fallbackPathReferenced = "referenced"

	fallbackDefinition = "98728c90-32c7-4049-8429-847dc0f4fe37"
	fallbackOther      = "2cc2c3b5-c2f8-45aa-a9e6-f90d85ae8352"
	fallbackSet        = "e3ec7e09-768c-4b64-882c-fcada3772047"
)

// fallbackARM fakes the built-in policy APIs. Every request is recorded as "<operation> <name>", with
// "@<version>" for a version: list, get (policy definitions) and list-set, get-set (policy sets).
type fallbackARM struct {
	listed      map[string][]*armpolicy.DefinitionVersion
	definitions map[string]*armpolicy.Definition
	versions    map[string]*armpolicy.DefinitionVersion

	setListed   map[string][]*armpolicy.SetDefinitionVersion
	sets        map[string]*armpolicy.SetDefinition
	setVersions map[string]*armpolicy.SetDefinitionVersion

	// afterListing is called when a version listing has returned, see afterListingPolicy.
	afterListing func()

	mu       sync.Mutex
	requests []string
}

// afterListingPolicy calls fallbackARM.afterListing once a version listing has returned. It runs in
// the caller's goroutine, outside the fake transport: the generated fakes panic with "send on closed
// channel" when the context is cancelled while they handle a request.
type afterListingPolicy struct {
	f *fallbackARM
}

func (p afterListingPolicy) Do(req *policy.Request) (*http.Response, error) {
	resp, err := req.Next()
	if p.f.afterListing != nil && strings.HasSuffix(req.Raw().URL.Path, "/versions") {
		p.f.afterListing()
	}

	return resp, err
}

func newFallbackARM() *fallbackARM {
	return &fallbackARM{
		listed:      map[string][]*armpolicy.DefinitionVersion{},
		definitions: map[string]*armpolicy.Definition{},
		versions:    map[string]*armpolicy.DefinitionVersion{},
		setListed:   map[string][]*armpolicy.SetDefinitionVersion{},
		sets:        map[string]*armpolicy.SetDefinition{},
		setVersions: map[string]*armpolicy.SetDefinitionVersion{},
	}
}

func (f *fallbackARM) record(request string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, request)
}

func (f *fallbackARM) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.requests...)
}

// addDefinition makes fallbackDefinition, with the given versions, available to get, and each of its
// versions to get on its own. Versions are given latest first, as Azure lists them.
func (f *fallbackARM) addDefinition(versions ...string) {
	f.definitions[fallbackDefinition] = &armpolicy.Definition{
		ID:   to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/" + fallbackDefinition),
		Name: to.Ptr(fallbackDefinition),
		Properties: &armpolicy.DefinitionProperties{
			Version:  to.Ptr(versions[0]),
			Versions: to.SliceOfPtrs(versions...),
		},
	}

	for _, v := range versions {
		f.versions[fallbackDefinition+"@"+v] = newPolicyDefinitionVersion(fallbackDefinition, v)
	}
}

// addReferencingSet makes the policy set fallbackSet available to get. It references
// fallbackDefinition with constraint.
func (f *fallbackARM) addReferencingSet(constraint string) {
	f.sets[fallbackSet] = fallbackPolicySet(fallbackSet, "1.8.0", nil, fallbackReference(fallbackDefinition, constraint))
}

func (f *fallbackARM) clientFactory(t *testing.T) *armpolicy.ClientFactory {
	t.Helper()

	srv := fake.ServerFactory{
		DefinitionsServer: fake.DefinitionsServer{
			GetBuiltIn: func(
				_ context.Context, name string, _ *armpolicy.DefinitionsClientGetBuiltInOptions,
			) (resp azfake.Responder[armpolicy.DefinitionsClientGetBuiltInResponse], errResp azfake.ErrorResponder) {
				f.record("get " + name)

				if def, ok := f.definitions[name]; ok {
					resp.SetResponse(http.StatusOK, armpolicy.DefinitionsClientGetBuiltInResponse{Definition: *def}, nil)
				} else {
					errResp.SetResponseError(http.StatusNotFound, "PolicyDefinitionNotFound")
				}

				return resp, errResp
			},
		},
		DefinitionVersionsServer: fake.DefinitionVersionsServer{
			NewListBuiltInPager: func(
				name string, _ *armpolicy.DefinitionVersionsClientListBuiltInOptions,
			) (resp azfake.PagerResponder[armpolicy.DefinitionVersionsClientListBuiltInResponse]) {
				f.record("list " + name)

				resp.AddPage(http.StatusOK, armpolicy.DefinitionVersionsClientListBuiltInResponse{
					DefinitionVersionListResult: armpolicy.DefinitionVersionListResult{Value: f.listed[name]},
				}, nil)

				return resp
			},
			GetBuiltIn: func(
				_ context.Context, name, version string, _ *armpolicy.DefinitionVersionsClientGetBuiltInOptions,
			) (resp azfake.Responder[armpolicy.DefinitionVersionsClientGetBuiltInResponse], errResp azfake.ErrorResponder) {
				f.record("get " + name + "@" + version)

				if v, ok := f.versions[name+"@"+version]; ok {
					resp.SetResponse(http.StatusOK, armpolicy.DefinitionVersionsClientGetBuiltInResponse{DefinitionVersion: *v}, nil)
				} else {
					errResp.SetResponseError(http.StatusNotFound, "PolicyDefinitionVersionNotFound")
				}

				return resp, errResp
			},
		},
		SetDefinitionsServer: fake.SetDefinitionsServer{
			GetBuiltIn: func(
				_ context.Context, name string, _ *armpolicy.SetDefinitionsClientGetBuiltInOptions,
			) (resp azfake.Responder[armpolicy.SetDefinitionsClientGetBuiltInResponse], errResp azfake.ErrorResponder) {
				f.record("get-set " + name)

				if set, ok := f.sets[name]; ok {
					resp.SetResponse(http.StatusOK, armpolicy.SetDefinitionsClientGetBuiltInResponse{SetDefinition: *set}, nil)
				} else {
					errResp.SetResponseError(http.StatusNotFound, "PolicySetDefinitionNotFound")
				}

				return resp, errResp
			},
		},
		SetDefinitionVersionsServer: fake.SetDefinitionVersionsServer{
			NewListBuiltInPager: func(
				name string, _ *armpolicy.SetDefinitionVersionsClientListBuiltInOptions,
			) (resp azfake.PagerResponder[armpolicy.SetDefinitionVersionsClientListBuiltInResponse]) {
				f.record("list-set " + name)

				resp.AddPage(http.StatusOK, armpolicy.SetDefinitionVersionsClientListBuiltInResponse{
					SetDefinitionVersionListResult: armpolicy.SetDefinitionVersionListResult{Value: f.setListed[name]},
				}, nil)

				return resp
			},
			GetBuiltIn: func(
				_ context.Context, name, version string, _ *armpolicy.SetDefinitionVersionsClientGetBuiltInOptions,
			) (resp azfake.Responder[armpolicy.SetDefinitionVersionsClientGetBuiltInResponse], errResp azfake.ErrorResponder) {
				f.record("get-set " + name + "@" + version)

				if v, ok := f.setVersions[name+"@"+version]; ok {
					resp.SetResponse(http.StatusOK, armpolicy.SetDefinitionVersionsClientGetBuiltInResponse{SetDefinitionVersion: *v}, nil)
				} else {
					errResp.SetResponseError(http.StatusNotFound, "PolicySetDefinitionVersionNotFound")
				}

				return resp, errResp
			},
		},
	}

	cf, err := armpolicy.NewClientFactory("", &azfake.TokenCredential{}, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport:       fake.NewServerFactoryTransport(&srv),
			PerCallPolicies: []policy.Policy{afterListingPolicy{f: f}},
		},
	})
	require.NoError(t, err)

	return cf
}

// fetch requests fallbackDefinition with constraint through path, and returns the AlzLib and the error.
func (f *fallbackARM) fetch(ctx context.Context, t *testing.T, path, constraint string) (*AlzLib, error) {
	t.Helper()

	az := NewAlzLib(nil)
	az.AddPolicyClient(f.clientFactory(t))

	var req BuiltInRequest

	switch path {
	case fallbackPathDirect:
		req = fallbackRequest(t, "policyDefinitions", fallbackDefinition, &constraint)
	case fallbackPathReferenced:
		f.addReferencingSet(constraint)

		req = fallbackRequest(t, "policySetDefinitions", fallbackSet, nil)
	default:
		t.Fatalf("unknown path %q", path)
	}

	var err error

	require.NotPanics(t, func() { err = az.GetDefinitionsFromAzure(ctx, []BuiltInRequest{req}) })

	return az, err
}

func fallbackRequest(t *testing.T, resourceType, name string, version *string) BuiltInRequest {
	t.Helper()

	id, err := arm.ParseResourceID("/providers/Microsoft.Authorization/" + resourceType + "/" + name)
	require.NoError(t, err)

	return BuiltInRequest{ResourceID: id, Version: version}
}

func fallbackReference(name, constraint string) *armpolicy.DefinitionReference {
	return &armpolicy.DefinitionReference{
		PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/" + name),
		DefinitionVersion:  to.Ptr(constraint),
	}
}

func fallbackPolicySet(
	name, version string, versions []string, refs ...*armpolicy.DefinitionReference,
) *armpolicy.SetDefinition {
	return &armpolicy.SetDefinition{
		ID:   to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/" + name),
		Name: to.Ptr(name),
		Properties: &armpolicy.SetDefinitionProperties{
			Description:       to.Ptr("unit test policy set definition"),
			DisplayName:       to.Ptr("Unit Test Policy Set Definition"),
			Version:           to.Ptr(version),
			Versions:          to.SliceOfPtrs(versions...),
			PolicyDefinitions: append([]*armpolicy.DefinitionReference{}, refs...),
		},
	}
}

// requestsFor returns the requests the paths make before the fallback.
func requestsFor(path string) []string {
	if path == fallbackPathReferenced {
		return []string{"get-set " + fallbackSet, "list " + fallbackDefinition}
	}

	return []string{"list " + fallbackDefinition}
}

// T1: a listing that provides the version is used; the fallback sends no request.
func TestVersionFallbackNotUsedWhenListingProvidesVersion(t *testing.T) {
	t.Parallel()

	for _, path := range []string{fallbackPathDirect, fallbackPathReferenced} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			f := newFallbackARM()
			f.listed[fallbackDefinition] = []*armpolicy.DefinitionVersion{newPolicyDefinitionVersion(fallbackDefinition, "1.0.2")}
			f.addDefinition("1.0.2")

			az, err := f.fetch(t.Context(), t, path, "1.*.*")
			require.NoError(t, err)
			assert.True(t, az.PolicyDefinitionExists(fallbackDefinition, to.Ptr("1.*.*")))
			assert.Equal(t, requestsFor(path), f.recorded())
		})
	}
}

// T2: an empty listing falls back to the definition, which provides the version.
func TestVersionFallbackEmptyListing(t *testing.T) {
	t.Parallel()

	for _, path := range []string{fallbackPathDirect, fallbackPathReferenced} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			f := newFallbackARM()
			f.addDefinition("1.0.2", "0.9.0")

			az, err := f.fetch(t.Context(), t, path, "1.*.*")
			require.NoError(t, err)

			pd := az.PolicyDefinition(fallbackDefinition, to.Ptr("1.*.*"))
			require.NotNil(t, pd)
			assert.Equal(t, fallbackDefinition, *pd.Name)
			assert.Equal(t, "1.0.2", *pd.Properties.Version)
			assert.Equal(t, append(requestsFor(path), "get "+fallbackDefinition, "get "+fallbackDefinition+"@1.0.2"), f.recorded())
		})
	}
}

// T3: versions listed under the requested name in another case are stored under the requested name,
// without a fallback.
func TestVersionFallbackListingUnderOtherCase(t *testing.T) {
	t.Parallel()

	for _, path := range []string{fallbackPathDirect, fallbackPathReferenced} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			f := newFallbackARM()
			f.listed[fallbackDefinition] = []*armpolicy.DefinitionVersion{
				newPolicyDefinitionVersion(strings.ToUpper(fallbackDefinition), "1.0.2"),
			}

			az, err := f.fetch(t.Context(), t, path, "1.*.*")
			require.NoError(t, err)

			pd := az.PolicyDefinition(fallbackDefinition, to.Ptr("1.*.*"))
			require.NotNil(t, pd)
			assert.Equal(t, fallbackDefinition, *pd.Name)
			assert.False(t, az.PolicyDefinitionExists(strings.ToUpper(fallbackDefinition), nil))
			assert.Equal(t, requestsFor(path), f.recorded())
		})
	}
}

// T4: versions of another definition in the listing are not used, even if one satisfies the
// constraint; the version is got from the definition instead.
func TestVersionFallbackListingOfOtherDefinition(t *testing.T) {
	t.Parallel()

	for _, path := range []string{fallbackPathDirect, fallbackPathReferenced} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			f := newFallbackARM()
			f.listed[fallbackDefinition] = []*armpolicy.DefinitionVersion{newPolicyDefinitionVersion(fallbackOther, "1.5.0")}
			f.addDefinition("1.0.2")

			az, err := f.fetch(t.Context(), t, path, "1.*.*")
			require.NoError(t, err)

			pd := az.PolicyDefinition(fallbackDefinition, to.Ptr("1.*.*"))
			require.NotNil(t, pd)
			assert.Equal(t, "1.0.2", *pd.Properties.Version)
			assert.False(t, az.PolicyDefinitionExists(fallbackOther, nil))
			assert.Equal(t, append(requestsFor(path), "get "+fallbackDefinition, "get "+fallbackDefinition+"@1.0.2"), f.recorded())
		})
	}
}

// T5: when the definition cannot be got either, the error describes the listing and the fallback.
func TestVersionFallbackDefinitionNotFound(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		listed      []*armpolicy.DefinitionVersion
		wantListing string
	}{
		{
			name:        "empty listing",
			wantListing: "version listing of `" + fallbackDefinition + "`: versions []",
		},
		{
			name:   "listing of another definition",
			listed: []*armpolicy.DefinitionVersion{newPolicyDefinitionVersion(fallbackOther, "1.5.0")},
			wantListing: "version listing of `" + fallbackDefinition + "`: versions [], " +
				"ignored versions of other definitions [" + fallbackOther + "@1.5.0]",
		},
	}

	for _, path := range []string{fallbackPathDirect, fallbackPathReferenced} {
		for _, tc := range cases {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				f := newFallbackARM()
				f.listed[fallbackDefinition] = tc.listed

				_, err := f.fetch(t.Context(), t, path, "1.*.*")
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantListing)
				require.ErrorContains(t, err, "getting the version from the definition instead: "+
					"getting built-in policy definition `"+fallbackDefinition+"`")

				var respErr *azcore.ResponseError
				require.ErrorAs(t, err, &respErr)
				assert.Equal(t, http.StatusNotFound, respErr.StatusCode)

				if path == fallbackPathReferenced {
					require.ErrorContains(t, err, "finding specific version constraint `1.*.*` of built-in policy definition "+
						"for `"+fallbackDefinition+"`, referenced in policy set `"+fallbackSet+"@1.8.0`. Versions available: []")
				} else {
					require.ErrorIs(t, err, assets.ErrNoVersionFound)
					require.ErrorContains(t, err, "Alzlib.getBuiltInPolicies: error getting specific version `1.*.*` "+
						"of built-in policy definition for `"+fallbackDefinition+"`")
				}

				assert.Equal(t, append(requestsFor(path), "get "+fallbackDefinition), f.recorded())
			})
		}
	}
}

// T6: when no version of the definition satisfies the constraint, the error lists its versions and no
// version is got.
func TestVersionFallbackNoVersionSatisfiesConstraint(t *testing.T) {
	t.Parallel()

	for _, path := range []string{fallbackPathDirect, fallbackPathReferenced} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			f := newFallbackARM()
			f.listed[fallbackDefinition] = []*armpolicy.DefinitionVersion{newPolicyDefinitionVersion(fallbackDefinition, "2.0.0")}
			f.addDefinition("2.0.0")

			_, err := f.fetch(t.Context(), t, path, "1.*.*")
			require.Error(t, err)
			require.ErrorIs(t, err, assets.ErrNoVersionFound)
			require.ErrorContains(t, err, "version listing of `"+fallbackDefinition+"`: versions [2.0.0]")
			require.ErrorContains(t, err, "getting the version from the definition instead: "+
				"built-in policy definition `"+fallbackDefinition+"`: versions [2.0.0]: no version found")
			assert.Equal(t, append(requestsFor(path), "get "+fallbackDefinition), f.recorded())
		})
	}
}

// T7: a policy set definition requested with a constraint, as Deploy-MCSB2-Monitoring requests MCSB v2,
// falls back to the set definition when its listing is empty.
func TestVersionFallbackPolicySetDefinition(t *testing.T) {
	t.Parallel()

	f := newFallbackARM()
	f.sets[fallbackSet] = fallbackPolicySet(fallbackSet, "1.8.0", []string{"1.8.0", "1.6.0"})

	for _, v := range []string{"1.8.0", "1.6.0"} {
		setVersion := newPolicySetDefinitionVersion(fallbackSet, v)
		setVersion.Properties.PolicyDefinitions = []*armpolicy.DefinitionReference{fallbackReference(fallbackDefinition, "1.*.*")}
		f.setVersions[fallbackSet+"@"+v] = setVersion
	}

	f.listed[fallbackDefinition] = []*armpolicy.DefinitionVersion{newPolicyDefinitionVersion(fallbackDefinition, "1.0.2")}

	az := NewAlzLib(nil)
	az.AddPolicyClient(f.clientFactory(t))

	req := fallbackRequest(t, "policySetDefinitions", fallbackSet, to.Ptr("1.*.*-preview"))
	require.NoError(t, az.GetDefinitionsFromAzure(t.Context(), []BuiltInRequest{req}))

	psd := az.PolicySetDefinition(fallbackSet, to.Ptr("1.*.*-preview"))
	require.NotNil(t, psd)
	assert.Equal(t, fallbackSet, *psd.Name)
	assert.Equal(t, "1.8.0", *psd.Properties.Version)
	assert.True(t, az.PolicyDefinitionExists(fallbackDefinition, to.Ptr("1.*.*")), "the references of the set are fetched")
	assert.Equal(t, []string{
		"list-set " + fallbackSet,
		"get-set " + fallbackSet,
		"get-set " + fallbackSet + "@1.8.0",
		"list " + fallbackDefinition,
	}, f.recorded())
}

// T7: when the set definition cannot be got either, the error describes the listing and the fallback.
func TestVersionFallbackPolicySetDefinitionNotFound(t *testing.T) {
	t.Parallel()

	f := newFallbackARM()
	az := NewAlzLib(nil)
	az.AddPolicyClient(f.clientFactory(t))

	req := fallbackRequest(t, "policySetDefinitions", fallbackSet, to.Ptr("1.*.*-preview"))
	err := az.GetDefinitionsFromAzure(t.Context(), []BuiltInRequest{req})
	require.Error(t, err)
	require.ErrorIs(t, err, assets.ErrNoVersionFound)
	require.ErrorContains(t, err, "Alzlib.getBuiltInPolicySets: error getting specific version `1.*.*-preview` "+
		"of built-in policy set definition for `"+fallbackSet+"`")
	require.ErrorContains(t, err, "version listing of `"+fallbackSet+"`: versions []")
	require.ErrorContains(t, err, "getting the version from the definition instead: "+
		"getting built-in policy set definition `"+fallbackSet+"`")
	assert.Equal(t, []string{"list-set " + fallbackSet, "get-set " + fallbackSet}, f.recorded())
}

// T8: a context cancelled once the listing has returned ends the request before the fallback sends a
// request.
func TestVersionFallbackHonoursCancellation(t *testing.T) {
	t.Parallel()

	for _, path := range []string{fallbackPathDirect, fallbackPathReferenced} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			f := newFallbackARM()
			f.addDefinition("1.0.2")
			f.afterListing = cancel

			_, err := f.fetch(ctx, t, path, "1.*.*")
			require.ErrorIs(t, err, context.Canceled)
			require.ErrorContains(t, err, "getting the version from the definition instead: context canceled")
			assert.Equal(t, requestsFor(path), f.recorded())
		})
	}
}

// T8: the fallback sends no request once the context is cancelled.
func TestVersionFallbackNotStartedWithCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	f := newFallbackARM()
	f.addDefinition("1.0.2")
	f.sets[fallbackSet] = fallbackPolicySet(fallbackSet, "1.8.0", []string{"1.8.0"})

	az := NewAlzLib(nil)
	az.AddPolicyClient(f.clientFactory(t))

	require.ErrorIs(t, az.addBuiltInPolicyDefinitionVersion(ctx, fallbackDefinition, "1.*.*"), context.Canceled)

	_, err := az.builtInPolicySetDefinitionVersion(ctx, fallbackSet, "1.*.*")
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, f.recorded())
}

// T10: the fallback selects the version that the listing would have provided, so the selection
// follows assets.VersionedPolicyCollection.GetVersion, including for preview constraints.
func TestVersionFallbackSelectsTheVersionTheListingWould(t *testing.T) {
	t.Parallel()

	versions := []string{"2.0.0", "1.3.0-preview", "1.2.0", "1.1.0-preview", "1.0.0"}

	for _, constraint := range []string{"1.*.*", "1.*.*-preview", "2.*.*"} {
		t.Run(constraint, func(t *testing.T) {
			t.Parallel()

			listing := newFallbackARM()
			for _, v := range versions {
				listing.listed[fallbackDefinition] = append(listing.listed[fallbackDefinition],
					newPolicyDefinitionVersion(fallbackDefinition, v))
			}

			fromListing, err := listing.fetch(t.Context(), t, fallbackPathDirect, constraint)
			require.NoError(t, err)

			fallback := newFallbackARM()
			fallback.addDefinition(versions...)

			fromDefinition, err := fallback.fetch(t.Context(), t, fallbackPathDirect, constraint)
			require.NoError(t, err)

			want := fromListing.PolicyDefinition(fallbackDefinition, &constraint)
			require.NotNil(t, want)

			got := fromDefinition.PolicyDefinition(fallbackDefinition, &constraint)
			require.NotNil(t, got)
			assert.Equal(t, *want.Properties.Version, *got.Properties.Version)
			assert.Contains(t, fallback.recorded(), "get "+fallbackDefinition)
		})
	}
}

// The version got must be the one requested; anything else is not stored.
func TestVersionFallbackRejectsAnotherVersion(t *testing.T) {
	t.Parallel()

	f := newFallbackARM()
	f.addDefinition("1.0.2")
	f.versions[fallbackDefinition+"@1.0.2"] = newPolicyDefinitionVersion(fallbackDefinition, "1.0.1")

	az, err := f.fetch(t.Context(), t, fallbackPathReferenced, "1.*.*")
	require.Error(t, err)
	require.ErrorContains(t, err, fmt.Sprintf("getting built-in definition `%s@1.0.2` returned `%s@1.0.1`",
		fallbackDefinition, fallbackDefinition))
	assert.False(t, az.PolicyDefinitionExists(fallbackDefinition, nil))
}

// B2 for the listing of a policy definition requested with a version constraint.
func TestCollectPolicyDefinitionVersionsUsesOnlyTheRequestedDefinition(t *testing.T) {
	t.Parallel()

	pager := &fakeDefinitionVersionsPager{pages: []definitionVersionPage{{
		response: armpolicy.DefinitionVersionsClientListBuiltInResponse{
			DefinitionVersionListResult: armpolicy.DefinitionVersionListResult{Value: []*armpolicy.DefinitionVersion{
				newPolicyDefinitionVersion(fallbackDefinition, "1.0.0"),
				newPolicyDefinitionVersion(strings.ToUpper(fallbackDefinition), "1.1.0"),
				newPolicyDefinitionVersion(fallbackOther, "1.2.0"),
			}},
		},
	}}}

	req := fallbackRequest(t, "policyDefinitions", fallbackDefinition, to.Ptr("1.*.*"))

	pdvs, listing, err := NewAlzLib(nil).collectPolicyDefinitionVersions(t.Context(), pager, req)
	require.NoError(t, err)
	assert.Equal(t, "[1.0.0 1.1.0]", fmt.Sprint(pdvs.Versions()))

	for pd := range pdvs.AllVersions() {
		assert.Equal(t, fallbackDefinition, *pd.Name)
	}

	assert.Equal(t, []string{"1.0.0", "1.1.0"}, listing.versions)
	assert.Equal(t, []string{fallbackOther + "@1.2.0"}, listing.ignored)
}

// B2 for the listing of a policy set definition requested with a version constraint.
func TestCollectPolicySetDefinitionVersionsUsesOnlyTheRequestedDefinition(t *testing.T) {
	t.Parallel()

	pager := &fakeSetDefinitionVersionsPager{pages: []setDefinitionVersionPage{{
		response: armpolicy.SetDefinitionVersionsClientListBuiltInResponse{
			SetDefinitionVersionListResult: armpolicy.SetDefinitionVersionListResult{Value: []*armpolicy.SetDefinitionVersion{
				newPolicySetDefinitionVersion(strings.ToUpper(fallbackSet), "1.8.0"),
				newPolicySetDefinitionVersion("other-set", "1.9.0"),
			}},
		},
	}}}

	req := fallbackRequest(t, "policySetDefinitions", fallbackSet, to.Ptr("1.*.*"))

	psdvs, listing, err := NewAlzLib(nil).collectPolicySetDefinitionVersions(t.Context(), pager, req)
	require.NoError(t, err)
	assert.Equal(t, "[1.8.0]", fmt.Sprint(psdvs.Versions()))

	for psd := range psdvs.AllVersions() {
		assert.Equal(t, fallbackSet, *psd.Name)
	}

	assert.Equal(t, []string{"other-set@1.9.0"}, listing.ignored)
}
