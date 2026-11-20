// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"golang.org/x/sync/errgroup"
)

// Listing the versions of each built-in policy definition takes one request per definition, about 700 for
// the alz architecture (Azure/Azure-Landing-Zones#4328). Azure lists the versions of every built-in policy
// definition in a few pages instead, but the REST API specification declares that listing as a single page,
// so the armpolicy client only gets the first page. The pages are therefore requested here, with the
// Azure Resource Manager client added by AddPolicyClientFromCredential.
//
// The bulk listing also lists versions that no longer exist: neither the definition (properties.versions)
// nor the version listing of the definition lists them, and getting them fails. They would change the
// version that some constraints resolve to, so only the versions that the definition lists are kept. The
// bulk listing of a definition is then the same as its version listing, and it is used in place of it:
// the versions are resolved and stored exactly as when they are listed one definition at a time.
// Policy set definitions cannot be listed in bulk, as the response exceeds the size that Azure allows.

const (
	// minBulkListedDefinitions is the number of policy definitions whose versions must be listed for the
	// bulk listing to be used. The bulk listing takes about 10 requests.
	minBulkListedDefinitions = 10
	// bulkListingPageSize is the number of definitions, or versions, requested per page: the most that
	// Azure returns.
	bulkListingPageSize = 1000
	// maxBulkListingPages is the most pages followed for each listing.
	maxBulkListingPages = 50
	// listPolicyDefinitionVersionsPath lists the versions of every built-in policy definition.
	listPolicyDefinitionVersionsPath = "/providers/Microsoft.Authorization/listPolicyDefinitionVersions"
	// policyDefinitionVersionsAPIVersion is the API version of armpolicy for policy definition versions.
	policyDefinitionVersionsAPIVersion = "2023-04-01"
	// alzlibModulePath identifies alzlib in the telemetry of its Azure Resource Manager client.
	alzlibModulePath = "github.com/Azure/alzlib"
	// unknownModuleVersion is used when the version of alzlib is not known, for example in tests.
	unknownModuleVersion = "v0.0.0"
)

// moduleVersionPattern matches the module versions that arm.NewClient accepts.
var moduleVersionPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+(?:-[a-zA-Z0-9_.-]+)?$`)

// bulkListing is the bulk listing of built-in policy definition versions for one GetDefinitionsFromAzure
// call. Its methods are safe to call on a nil bulkListing, which never lists anything.
type bulkListing struct {
	armClient    *arm.Client
	policyClient *armpolicy.ClientFactory
	attempted    bool
	// versions holds the listed versions of each built-in policy definition, as returned by Azure, by lower
	// case name. A version is only decoded when its definition is listed, which keeps memory use low. It is
	// nil until the versions have been listed, and if listing them failed.
	versions map[string][]json.RawMessage
}

// newBulkListing returns the bulk listing for a GetDefinitionsFromAzure call, or nil unless the clients
// were added with AddPolicyClientFromCredential.
func (az *AlzLib) newBulkListing() *bulkListing {
	az.mu.RLock()
	defer az.mu.RUnlock()

	if az.clients.armClient == nil || az.clients.policyClient == nil {
		return nil
	}

	return &bulkListing{armClient: az.clients.armClient, policyClient: az.clients.policyClient}
}

// prepare lists the versions of every built-in policy definition, the first time in the call that the
// versions of at least minBulkListedDefinitions definitions need to be listed, as counted by
// definitionsToList. A failed listing is not tried again in the same call.
func (b *bulkListing) prepare(ctx context.Context, parallelism int, definitionsToList func() int) {
	if b == nil || b.attempted || definitionsToList() < minBulkListedDefinitions {
		return
	}

	b.attempted = true

	versions, err := listBuiltInPolicyDefinitionVersions(ctx, b.armClient, b.policyClient, parallelism)
	if err != nil {
		// The bulk listing only saves requests: the versions are listed one definition at a time instead.
		return
	}

	b.versions = versions
}

// listing returns the versions of the named policy definition, and whether the bulk listing has them.
func (b *bulkListing) listing(name string) ([]json.RawMessage, bool) {
	if b == nil || b.versions == nil {
		return nil, false
	}

	versions, ok := b.versions[strings.ToLower(name)]

	return versions, ok
}

// policyDefinitionsToList returns the number of distinct policy definitions whose versions would be listed
// for reqs: those requested with a version that neither AlzLib nor the cache has.
func (az *AlzLib) policyDefinitionsToList(reqs []BuiltInRequest) int {
	names := make(map[string]struct{}, len(reqs))

	for _, req := range reqs {
		name := req.ResourceID.Name
		if req.Version == nil || az.PolicyDefinitionExists(name, req.Version) {
			continue
		}

		if pd, err := az.policyDefinitionFromCache(name, req.Version); err == nil && pd != nil {
			continue
		}

		names[strings.ToLower(name)] = struct{}{}
	}

	return len(names)
}

// policyDefinitionVersionsPager returns a pager over the versions of the built-in policy definition name:
// its bulk listing if the call has one for it, otherwise its version listing.
func (az *AlzLib) policyDefinitionVersionsPager(
	client *armpolicy.DefinitionVersionsClient,
	name string,
) policyDefinitionVersionsPager {
	if versions, ok := az.bulk.listing(name); ok {
		return &bulkPolicyDefinitionVersionsPager{versions: versions}
	}

	return client.NewListBuiltInPager(name, nil)
}

// bulkPolicyDefinitionVersionsPager returns the bulk listed versions of a policy definition as one page.
type bulkPolicyDefinitionVersionsPager struct {
	versions []json.RawMessage
	done     bool
}

// More reports whether the page has not been returned yet.
func (p *bulkPolicyDefinitionVersionsPager) More() bool {
	return !p.done
}

// NextPage returns the versions, unless ctx is done. They are decoded as the version listing decodes them.
func (p *bulkPolicyDefinitionVersionsPager) NextPage(
	ctx context.Context,
) (armpolicy.DefinitionVersionsClientListBuiltInResponse, error) {
	var resp armpolicy.DefinitionVersionsClientListBuiltInResponse

	if err := ctx.Err(); err != nil {
		return resp, err
	}

	p.done = true
	resp.Value = make([]*armpolicy.DefinitionVersion, 0, len(p.versions))

	for _, raw := range p.versions {
		v := new(armpolicy.DefinitionVersion)
		if err := json.Unmarshal(raw, v); err != nil {
			return armpolicy.DefinitionVersionsClientListBuiltInResponse{}, fmt.Errorf(
				"reading a bulk listed built-in policy definition version: %w", err,
			)
		}

		resp.Value = append(resp.Value, v)
	}

	return resp, nil
}

// listBuiltInPolicyDefinitionVersions lists the versions of every built-in policy definition, and every
// built-in policy definition, and returns the listed versions that each definition lists, by lower case
// definition name. The two listings are made concurrently, unless parallelism is 1.
func listBuiltInPolicyDefinitionVersions(
	ctx context.Context,
	armClient *arm.Client,
	policyClient *armpolicy.ClientFactory,
	parallelism int,
) (map[string][]json.RawMessage, error) {
	var (
		listed  []listedVersion
		defined map[string]map[string]bool
	)

	grp, grpCtx := errgroup.WithContext(ctx)
	grp.SetLimit(max(parallelism, 1))

	grp.Go(func() (err error) {
		listed, err = listAllBuiltInPolicyDefinitionVersions(grpCtx, armClient)
		return err
	})

	grp.Go(func() (err error) {
		defined, err = builtInPolicyDefinitionVersionsByName(grpCtx, policyClient)
		return err
	})

	if err := grp.Wait(); err != nil {
		return nil, err
	}

	return definedVersionsByName(listed, defined), nil
}

// listedVersion is a policy definition version from the bulk listing, as returned by Azure.
type listedVersion struct {
	// name is the lower case definition name, taken from the resource ID as
	// NewPolicyDefinitionFromVersionValidate takes it.
	name    string
	version string
	raw     json.RawMessage
}

// listedVersionPage is a page of the bulk listing of built-in policy definition versions.
type listedVersionPage struct {
	NextLink *string           `json:"nextLink"`
	Value    []json.RawMessage `json:"value"`
}

// listAllBuiltInPolicyDefinitionVersions lists the versions of every built-in policy definition. Each
// nextLink is requested with POST, like the first page. Versions without a resource ID and version are
// left out.
func listAllBuiltInPolicyDefinitionVersions(ctx context.Context, client *arm.Client) ([]listedVersion, error) {
	endpoint, err := url.Parse(client.Endpoint())
	if err != nil {
		return nil, fmt.Errorf("parsing the Azure Resource Manager endpoint: %w", err)
	}

	query := url.Values{}
	query.Set("api-version", policyDefinitionVersionsAPIVersion)
	query.Set("$top", strconv.Itoa(bulkListingPageSize))
	link := runtime.JoinPaths(client.Endpoint(), listPolicyDefinitionVersionsPath) + "?" + query.Encode()

	var versions []listedVersion

	for page := 0; link != ""; page++ {
		if page == maxBulkListingPages {
			return nil, fmt.Errorf("listing built-in policy definition versions: more than %d pages", maxBulkListingPages)
		}

		result, err := listBuiltInPolicyDefinitionVersionsPage(ctx, client, link)
		if err != nil {
			return nil, err
		}

		for _, raw := range result.Value {
			if v, ok := newListedVersion(raw); ok {
				versions = append(versions, v)
			}
		}

		link = to.ValOrZero(result.NextLink)

		if link != "" {
			if err := checkNextLink(endpoint, link); err != nil {
				return nil, err
			}
		}
	}

	return versions, nil
}

// newListedVersion returns the listed policy definition version raw, and whether it has a resource ID
// and a version.
func newListedVersion(raw json.RawMessage) (listedVersion, bool) {
	var v struct {
		ID         *string `json:"id"`
		Properties *struct {
			Version *string `json:"version"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(raw, &v); err != nil || v.ID == nil || v.Properties == nil || v.Properties.Version == nil {
		return listedVersion{}, false
	}

	resID, err := arm.ParseResourceID(*v.ID)
	if err != nil || resID.Parent == nil {
		return listedVersion{}, false
	}

	return listedVersion{name: strings.ToLower(resID.Parent.Name), version: *v.Properties.Version, raw: raw}, true
}

// listBuiltInPolicyDefinitionVersionsPage gets one page of the bulk listing of built-in policy definition
// versions.
func listBuiltInPolicyDefinitionVersionsPage(
	ctx context.Context,
	client *arm.Client,
	link string,
) (listedVersionPage, error) {
	var result listedVersionPage

	req, err := runtime.NewRequest(ctx, http.MethodPost, link)
	if err != nil {
		return result, fmt.Errorf("creating the request listing built-in policy definition versions: %w", err)
	}

	req.Raw().Header["Accept"] = []string{"application/json"}

	resp, err := client.Pipeline().Do(req)
	if err != nil {
		return result, fmt.Errorf("listing built-in policy definition versions: %w", err)
	}

	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return result, fmt.Errorf("listing built-in policy definition versions: %w", runtime.NewResponseError(resp))
	}

	if err := runtime.UnmarshalAsJSON(resp, &result); err != nil {
		return result, fmt.Errorf("reading the built-in policy definition versions: %w", err)
	}

	return result, nil
}

// checkNextLink returns an error unless link is an https URL on the host of the Azure Resource Manager
// endpoint: the pipeline sends the bearer token with every request.
func checkNextLink(endpoint *url.URL, link string) error {
	next, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("parsing the nextLink of the built-in policy definition versions: %w", err)
	}

	if next.Scheme != "https" || !strings.EqualFold(next.Scheme, endpoint.Scheme) ||
		!strings.EqualFold(next.Host, endpoint.Host) {
		return fmt.Errorf(
			"the nextLink of the built-in policy definition versions is not on the Azure Resource Manager endpoint %s",
			endpoint.Redacted(),
		)
	}

	return nil
}

// builtInPolicyDefinitionVersionsByName lists every built-in policy definition and returns the versions
// that each one lists, by lower case name, taken like selectBuiltInPolicyDefinitionVersion takes them. A
// name listed twice is left out.
func builtInPolicyDefinitionVersionsByName(
	ctx context.Context,
	client *armpolicy.ClientFactory,
) (map[string]map[string]bool, error) {
	pager := client.NewDefinitionsClient().NewListBuiltInPager(&armpolicy.DefinitionsClientListBuiltInOptions{
		Top: to.Ptr[int32](bulkListingPageSize),
	})

	versions := make(map[string]map[string]bool)
	listedTwice := make(map[string]bool)

	for page := 0; pager.More(); page++ {
		if page == maxBulkListingPages {
			return nil, fmt.Errorf("listing built-in policy definitions: more than %d pages", maxBulkListingPages)
		}

		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing built-in policy definitions: %w", err)
		}

		for _, def := range resp.Value {
			if def == nil || def.Name == nil {
				continue
			}

			name := strings.ToLower(*def.Name)
			if _, ok := versions[name]; ok {
				listedTwice[name] = true
				continue
			}

			versions[name] = definitionVersions(def)
		}
	}

	for name := range listedTwice {
		delete(versions, name)
	}

	return versions, nil
}

// definitionVersions returns the versions that a policy definition lists, including its own version.
func definitionVersions(def *armpolicy.Definition) map[string]bool {
	res := make(map[string]bool)
	if def.Properties == nil {
		return res
	}

	for _, v := range append(slices.Clone(def.Properties.Versions), def.Properties.Version) {
		if v != nil && *v != "" {
			res[*v] = true
		}
	}

	return res
}

// definedVersionsByName returns the listed versions that their definition lists, by lower case definition
// name. A definition is left out if any version it lists is not listed, or is listed twice with different
// content (Azure/Azure-Landing-Zones#4327): its versions are then listed on their own, as without the bulk
// listing.
func definedVersionsByName(listed []listedVersion, defined map[string]map[string]bool) map[string][]json.RawMessage {
	byName := make(map[string][]listedVersion)
	conflicting := make(map[string]bool)

	for _, v := range listed {
		if !defined[v.name][v.version] {
			continue
		}

		i := slices.IndexFunc(byName[v.name], func(e listedVersion) bool { return e.version == v.version })
		if i < 0 {
			byName[v.name] = append(byName[v.name], v)
			continue
		}

		if !bytes.Equal(byName[v.name][i].raw, v.raw) {
			conflicting[v.name] = true
		}
	}

	res := make(map[string][]json.RawMessage, len(byName))

	for name, versions := range byName {
		if conflicting[name] || len(versions) != len(defined[name]) {
			continue
		}

		for _, v := range versions {
			res[name] = append(res[name], v.raw)
		}
	}

	return res
}

// alzlibModuleVersion returns the version of the alzlib module in the running program, for the telemetry of
// its Azure Resource Manager client.
func alzlibModuleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return unknownModuleVersion
	}

	var version string
	if info.Main.Path == alzlibModulePath {
		version = info.Main.Version
	}

	for _, dep := range info.Deps {
		if dep.Path == alzlibModulePath {
			version = dep.Version
		}
	}

	// Build metadata, such as +dirty, is not accepted.
	version, _, _ = strings.Cut(version, "+")
	if !moduleVersionPattern.MatchString(version) {
		return unknownModuleVersion
	}

	return version
}
