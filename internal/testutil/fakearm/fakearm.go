// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Package fakearm provides an in-process fake of the Azure Resource Manager built-in policy APIs.
// It is intended for tests that need deterministic, offline responses and want to observe how many
// requests are made and how many run concurrently.
package fakearm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

const (
	policyDefinitionIDFmt    = "/providers/Microsoft.Authorization/policyDefinitions/%s"
	policySetDefinitionIDFmt = "/providers/Microsoft.Authorization/policySetDefinitions/%s"
	policyDefinitionsSeg     = "policydefinitions"
	policySetDefinitionsSeg  = "policysetdefinitions"
	versionsSeg              = "versions"
	listPathSegments         = 3
	versionsPathSegments     = 5
	tokenLifetime            = time.Hour

	listPolicyDefinitionVersionsSeg = "listpolicydefinitionversions"
	// defaultListPageSize and maxListPageSize are the page sizes of the Azure listings, without $top and
	// with the largest $top accepted.
	defaultListPageSize = 500
	maxListPageSize     = 1000
)

// Reference is a policy definition referenced by a fake policy set definition.
type Reference struct {
	// Name is the name of the referenced policy definition.
	Name string
	// Version is the optional version constraint of the reference, e.g. `1.*.*`.
	Version *string
}

type policyDefinitionEntry struct {
	name     string
	versions []string
}

type setDefinition struct {
	name     string
	versions []string
	refs     []Reference
}

// Server is a fake ARM endpoint for built-in policy (set) definitions.
// It implements [policy.Transporter] and is safe for concurrent use.
// Besides the requests for one definition, it serves the listing of every built-in policy definition
// (GET .../policyDefinitions) and the bulk listing of every built-in policy definition version
// (POST .../listPolicyDefinitionVersions), a page at a time, as Azure does.
type Server struct {
	// Latency is added to every request. The request context is honoured while waiting.
	Latency time.Duration

	mu                   sync.Mutex
	policyDefinitions    map[string]policyDefinitionEntry
	policySetDefinitions map[string]setDefinition
	failures             map[string]int
	throttles            map[string]throttle
	calls                map[string]int
	totalCalls           int
	inFlight             int
	peakInFlight         int

	listPageSize          int
	listCalls             map[string]int
	listFailures          map[string]listFailure
	phantomVersions       map[string][]string
	omittedFromBulk       map[string][]string
	listedTwice           map[string]string
	definitionListedTwice map[string][]string
	bulkNextLinkBase      *url.URL
}

// throttle describes how many more requests for a definition are answered with HTTP 429.
type throttle struct {
	remaining  int
	retryAfter string
}

// listFailure is the error response to one page request of a listing.
type listFailure struct {
	page   int
	status int
	code   string
}

// New returns an empty fake ARM server.
func New() *Server {
	return &Server{
		policyDefinitions:     make(map[string]policyDefinitionEntry),
		policySetDefinitions:  make(map[string]setDefinition),
		failures:              make(map[string]int),
		throttles:             make(map[string]throttle),
		calls:                 make(map[string]int),
		listCalls:             make(map[string]int),
		listFailures:          make(map[string]listFailure),
		phantomVersions:       make(map[string][]string),
		omittedFromBulk:       make(map[string][]string),
		listedTwice:           make(map[string]string),
		definitionListedTwice: make(map[string][]string),
	}
}

// AddPolicyDefinition registers a built-in policy definition with the supplied versions.
// The last version is returned as the latest version.
func (s *Server) AddPolicyDefinition(name string, versions ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.policyDefinitions[strings.ToLower(name)] = policyDefinitionEntry{name: name, versions: versions}
}

// AddPolicySetDefinition registers a built-in policy set definition with the supplied versions and
// referenced policy definitions. The last version is returned as the latest version.
func (s *Server) AddPolicySetDefinition(name string, versions []string, refs ...Reference) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.policySetDefinitions[strings.ToLower(name)] = setDefinition{name: name, versions: versions, refs: refs}
}

// FailDefinition makes every request for the named definition return the supplied HTTP status code.
func (s *Server) FailDefinition(name string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failures[strings.ToLower(name)] = status
}

// ThrottleDefinition makes the next times requests for the named definition return HTTP 429
// TooManyRequests, as Azure Resource Manager does when throttling. A negative times throttles every
// request. retryAfter is sent as the Retry-After header unless it is empty.
func (s *Server) ThrottleDefinition(name string, times int, retryAfter string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.throttles[strings.ToLower(name)] = throttle{remaining: times, retryAfter: retryAfter}
}

// SetListPageSize limits the number of entries in each page of the listings, below the page size that
// $top requests. Zero removes the limit.
func (s *Server) SetListPageSize(size int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.listPageSize = size
}

// AddPhantomPolicyDefinitionVersion makes the bulk listing of built-in policy definition versions list a
// version of the named policy definition that does not exist: neither the definition nor its version
// listing lists it, as seen in Azure.
func (s *Server) AddPhantomPolicyDefinitionVersion(name, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := strings.ToLower(name)
	s.phantomVersions[key] = append(s.phantomVersions[key], version)
}

// OmitFromBulkVersionListing leaves the supplied versions of the named policy definition out of the bulk
// listing, or all of its versions if none is supplied.
func (s *Server) OmitFromBulkVersionListing(name string, versions ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A nil slice leaves out every version.
	s.omittedFromBulk[strings.ToLower(name)] = slices.Clone(versions)
}

// ListTwiceInBulkVersionListing makes the bulk listing list a version of the named policy definition a
// second time, with different content, just before the version itself.
func (s *Server) ListTwiceInBulkVersionListing(name, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.listedTwice[strings.ToLower(name)] = version
}

// ListTwiceInDefinitionListing makes the listing of built-in policy definitions list the named policy
// definition a second time, with the supplied versions.
func (s *Server) ListTwiceInDefinitionListing(name string, versions ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.definitionListedTwice[strings.ToLower(name)] = slices.Clone(versions)
}

// FailBulkVersionListing answers the request with index page, counting from 0, for a page of the bulk
// listing of built-in policy definition versions with the supplied HTTP status code and error code.
func (s *Server) FailBulkVersionListing(page, status int, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.listFailures[listPolicyDefinitionVersionsSeg] = listFailure{page: page, status: status, code: code}
}

// FailDefinitionListing answers the request with index page, counting from 0, for a page of the listing
// of built-in policy definitions with the supplied HTTP status code and error code.
func (s *Server) FailDefinitionListing(page, status int, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.listFailures[policyDefinitionsSeg] = listFailure{page: page, status: status, code: code}
}

// SetBulkVersionListingNextLinkBase replaces the scheme and host of the nextLink of each page of the bulk
// listing of built-in policy definition versions with those of base.
func (s *Server) SetBulkVersionListingNextLinkBase(base string) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("fakearm: parsing nextLink base: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.bulkNextLinkBase = u

	return nil
}

// Calls returns the number of requests made for the named definition.
func (s *Server) Calls(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.calls[strings.ToLower(name)]
}

// AllCalls returns a copy of the number of requests made per lower case definition name.
func (s *Server) AllCalls() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return maps.Clone(s.calls)
}

// TotalCalls returns the total number of requests made.
func (s *Server) TotalCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.totalCalls
}

// PeakInFlight returns the highest number of requests that were in flight at the same time.
func (s *Server) PeakInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.peakInFlight
}

// BulkVersionListingCalls returns the number of requests for a page of the bulk listing of built-in policy
// definition versions.
func (s *Server) BulkVersionListingCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.listCalls[listPolicyDefinitionVersionsSeg]
}

// DefinitionListingCalls returns the number of requests for a page of the listing of built-in policy
// definitions.
func (s *Server) DefinitionListingCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.listCalls[policyDefinitionsSeg]
}

// Credential returns a credential for clients of this server.
func (s *Server) Credential() azcore.TokenCredential {
	return credential{}
}

// ClientOptions returns client options that send all requests to this server.
// Retries are disabled so that injected failures surface immediately.
func (s *Server) ClientOptions() *arm.ClientOptions {
	return &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Transport: s,
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
	}
}

// NewClientFactory returns an armpolicy client factory that sends all requests to this server.
// Retries are disabled so that injected failures surface immediately.
func (s *Server) NewClientFactory() (*armpolicy.ClientFactory, error) {
	cf, err := armpolicy.NewClientFactory("", credential{}, s.ClientOptions())
	if err != nil {
		return nil, fmt.Errorf("fakearm: creating client factory: %w", err)
	}

	return cf, nil
}

// Do implements [policy.Transporter].
func (s *Server) Do(req *http.Request) (*http.Response, error) {
	segs := strings.Split(strings.Trim(strings.ToLower(req.URL.Path), "/"), "/")
	// Expected: providers/microsoft.authorization/<type>[/<name>[/versions]].
	if len(segs) < listPathSegments || segs[0] != "providers" || segs[1] != "microsoft.authorization" {
		return jsonResponse(req, http.StatusNotFound, errorBody("PathNotFound", req.URL.Path))
	}

	if len(segs) == listPathSegments {
		return s.list(req, segs[2])
	}

	defType, name := segs[2], segs[3]
	listVersions := len(segs) == versionsPathSegments && segs[4] == versionsSeg

	s.begin(name)
	defer s.end()

	if err := s.wait(req); err != nil {
		return nil, err
	}

	s.mu.Lock()
	status, fail := s.failures[name]
	thr, throttled := s.throttles[name]

	if throttled && thr.remaining != 0 {
		thr.remaining--
		s.throttles[name] = thr
	} else {
		throttled = false
	}

	pd, pdOK := s.policyDefinitions[name]
	psd, psdOK := s.policySetDefinitions[name]
	s.mu.Unlock()

	if fail {
		return jsonResponse(req, status, errorBody("InjectedFailure", name))
	}

	if throttled {
		resp, err := jsonResponse(req, http.StatusTooManyRequests, errorBody("TenantRequestsThrottled", name))
		if resp != nil && thr.retryAfter != "" {
			resp.Header.Set("Retry-After", thr.retryAfter)
		}

		return resp, err
	}

	switch {
	case defType == policyDefinitionsSeg && pdOK:
		if listVersions {
			return jsonResponse(req, http.StatusOK, policyDefinitionVersionList(pd.name, pd.versions))
		}

		return jsonResponse(req, http.StatusOK, policyDefinition(pd.name, latest(pd.versions)))
	case defType == policySetDefinitionsSeg && psdOK:
		if listVersions {
			return jsonResponse(req, http.StatusOK, policySetDefinitionVersionList(psd))
		}

		return jsonResponse(req, http.StatusOK, policySetDefinition(psd.name, latest(psd.versions), psd.refs))
	}

	return jsonResponse(req, http.StatusNotFound, errorBody("PolicyDefinitionNotFound", name))
}

// list serves a page of the listing of built-in policy definitions or of the bulk listing of built-in
// policy definition versions. The $skiptoken of a nextLink is the index of the first entry of its page.
func (s *Server) list(req *http.Request, route string) (*http.Response, error) {
	method := http.MethodGet
	if route == listPolicyDefinitionVersionsSeg {
		method = http.MethodPost
	} else if route != policyDefinitionsSeg {
		return jsonResponse(req, http.StatusNotFound, errorBody("PathNotFound", req.URL.Path))
	}

	page := s.beginList(route)
	defer s.end()

	if err := s.wait(req); err != nil {
		return nil, err
	}

	if req.Method != method {
		return jsonResponse(req, http.StatusMethodNotAllowed, errorBody("HttpMethodNotSupported", req.URL.Path))
	}

	s.mu.Lock()
	failure, fail := s.listFailures[route]
	entries := s.listEntries(route)
	pageSize := s.listPageSize

	var nextLinkBase *url.URL
	if route == listPolicyDefinitionVersionsSeg {
		nextLinkBase = s.bulkNextLinkBase
	}
	s.mu.Unlock()

	if fail && failure.page == page {
		return jsonResponse(req, failure.status, errorBody(failure.code, route))
	}

	return listPage(req, entries, pageSize, nextLinkBase)
}

// listEntries returns every entry of a listing, in name order. It must be called with s.mu held.
func (s *Server) listEntries(route string) []any {
	keys := slices.Sorted(maps.Keys(s.policyDefinitions))
	entries := make([]any, 0, len(keys))

	for _, key := range keys {
		pd := s.policyDefinitions[key]

		if route == policyDefinitionsSeg {
			entries = append(entries, listedPolicyDefinition(pd.name, pd.versions))

			if versions, ok := s.definitionListedTwice[key]; ok {
				entries = append(entries, listedPolicyDefinition(pd.name, versions))
			}

			continue
		}

		for _, v := range s.phantomVersions[key] {
			entries = append(entries, policyDefinitionVersion(pd.name, v))
		}

		omitted, omit := s.omittedFromBulk[key]

		for _, v := range pd.versions {
			if omit && (omitted == nil || slices.Contains(omitted, v)) {
				continue
			}

			if s.listedTwice[key] == v {
				twice := policyDefinitionVersion(pd.name, v)
				props := policyDefinitionProperties(pd.name, v)
				props["displayName"] = pd.name + " listed twice"
				twice["properties"] = props
				entries = append(entries, twice)
			}

			entries = append(entries, policyDefinitionVersion(pd.name, v))
		}
	}

	return entries
}

// listPage returns the page of entries that req asks for, honouring $top like Azure, and limited to
// maxPageSize entries unless it is zero.
func listPage(req *http.Request, entries []any, maxPageSize int, nextLinkBase *url.URL) (*http.Response, error) {
	query := req.URL.Query()
	size := defaultListPageSize

	if top := query.Get("$top"); top != "" {
		n, err := strconv.Atoi(top)
		if err != nil || n < 1 || n > maxListPageSize {
			return jsonResponse(req, http.StatusBadRequest, errorBody("InvalidTopInQueryString", top))
		}

		size = n
	}

	if maxPageSize > 0 {
		size = min(size, maxPageSize)
	}

	start, _ := strconv.Atoi(query.Get("$skiptoken"))
	start = min(max(start, 0), len(entries))
	end := min(start+size, len(entries))
	body := map[string]any{"value": entries[start:end]}

	if end < len(entries) {
		query.Set("$skiptoken", strconv.Itoa(end))

		next := *req.URL
		next.RawQuery = query.Encode()

		if nextLinkBase != nil {
			next.Scheme, next.Host = nextLinkBase.Scheme, nextLinkBase.Host
		}

		body["nextLink"] = next.String()
	}

	return jsonResponse(req, http.StatusOK, body)
}

// wait adds the configured latency, unless the request context is done first.
func (s *Server) wait(req *http.Request) error {
	if s.Latency <= 0 {
		return nil
	}

	select {
	case <-req.Context().Done():
		return fmt.Errorf("fakearm: %w", req.Context().Err())
	case <-time.After(s.Latency):
		return nil
	}
}

func (s *Server) begin(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls[name]++
	s.totalCalls++
	s.inFlight++
	s.peakInFlight = max(s.peakInFlight, s.inFlight)
}

// beginList records a request for a page of a listing, and returns the number of earlier requests for it.
func (s *Server) beginList(route string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	page := s.listCalls[route]
	s.listCalls[route]++
	s.totalCalls++
	s.inFlight++
	s.peakInFlight = max(s.peakInFlight, s.inFlight)

	return page
}

func (s *Server) end() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.inFlight--
}

func latest(versions []string) string {
	if len(versions) == 0 {
		return "1.0.0"
	}

	return versions[len(versions)-1]
}

func policyDefinitionProperties(name, version string) map[string]any {
	return map[string]any{
		"displayName": name,
		"description": name + " description",
		"policyType":  "BuiltIn",
		"mode":        "All",
		"metadata":    map[string]any{},
		"parameters":  map[string]any{},
		"policyRule": map[string]any{
			"if":   map[string]any{"field": "type", "equals": "Microsoft.Resources/subscriptions"},
			"then": map[string]any{"effect": "audit"},
		},
		"version": version,
	}
}

func policyDefinition(name, version string) map[string]any {
	return map[string]any{
		"id":         fmt.Sprintf(policyDefinitionIDFmt, name),
		"name":       name,
		"type":       "Microsoft.Authorization/policyDefinitions",
		"properties": policyDefinitionProperties(name, version),
	}
}

// listedPolicyDefinition returns a policy definition as the listing of built-in policy definitions has it:
// with every version it has.
func listedPolicyDefinition(name string, versions []string) map[string]any {
	def := policyDefinition(name, latest(versions))
	props := policyDefinitionProperties(name, latest(versions))
	props["versions"] = slices.Clone(versions)
	def["properties"] = props

	return def
}

// policyDefinitionVersion returns a policy definition version, the same in its version listing and in the
// bulk listing.
func policyDefinitionVersion(name, version string) map[string]any {
	return map[string]any{
		"id":         fmt.Sprintf(policyDefinitionIDFmt+"/versions/%s", name, version),
		"name":       version,
		"type":       "Microsoft.Authorization/policyDefinitions/versions",
		"properties": policyDefinitionProperties(name, version),
	}
}

func policyDefinitionVersionList(name string, versions []string) map[string]any {
	value := make([]any, 0, len(versions))
	for _, v := range versions {
		value = append(value, policyDefinitionVersion(name, v))
	}

	return map[string]any{"value": value}
}

func policySetDefinitionProperties(name, version string, refs []Reference) map[string]any {
	pdRefs := make([]any, 0, len(refs))

	for i, ref := range refs {
		r := map[string]any{
			"policyDefinitionId":          fmt.Sprintf(policyDefinitionIDFmt, ref.Name),
			"policyDefinitionReferenceId": fmt.Sprintf("ref-%d", i),
			"parameters":                  map[string]any{},
		}
		if ref.Version != nil {
			r["definitionVersion"] = *ref.Version
		}

		pdRefs = append(pdRefs, r)
	}

	return map[string]any{
		"displayName":       name,
		"description":       name + " description",
		"policyType":        "BuiltIn",
		"metadata":          map[string]any{},
		"parameters":        map[string]any{},
		"policyDefinitions": pdRefs,
		"version":           version,
	}
}

func policySetDefinition(name, version string, refs []Reference) map[string]any {
	return map[string]any{
		"id":         fmt.Sprintf(policySetDefinitionIDFmt, name),
		"name":       name,
		"type":       "Microsoft.Authorization/policySetDefinitions",
		"properties": policySetDefinitionProperties(name, version, refs),
	}
}

func policySetDefinitionVersionList(psd setDefinition) map[string]any {
	value := make([]any, 0, len(psd.versions))
	for _, v := range psd.versions {
		value = append(value, map[string]any{
			"id":         fmt.Sprintf(policySetDefinitionIDFmt+"/versions/%s", psd.name, v),
			"name":       v,
			"type":       "Microsoft.Authorization/policySetDefinitions/versions",
			"properties": policySetDefinitionProperties(psd.name, v, psd.refs),
		})
	}

	return map[string]any{"value": value}
}

func errorBody(code, target string) map[string]any {
	return map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": "fakearm: " + target,
		},
	}
}

func jsonResponse(req *http.Request, status int, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("fakearm: marshalling response: %w", err)
	}

	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(b)),
		ContentLength: int64(len(b)),
		Request:       req,
	}, nil
}

// credential is a fake azcore.TokenCredential that always returns a static token.
type credential struct{}

// GetToken implements azcore.TokenCredential.
func (credential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake", ExpiresOn: time.Now().Add(tokenLifetime)}, nil
}
