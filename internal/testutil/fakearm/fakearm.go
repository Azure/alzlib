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
	minPathSegments          = 4
	versionsPathSegments     = 5
	tokenLifetime            = time.Hour
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
type Server struct {
	// Latency is added to every request. The request context is honoured while waiting.
	Latency time.Duration

	mu                   sync.Mutex
	policyDefinitions    map[string]policyDefinitionEntry
	policySetDefinitions map[string]setDefinition
	failures             map[string]int
	calls                map[string]int
	totalCalls           int
	inFlight             int
	peakInFlight         int
}

// New returns an empty fake ARM server.
func New() *Server {
	return &Server{
		policyDefinitions:    make(map[string]policyDefinitionEntry),
		policySetDefinitions: make(map[string]setDefinition),
		failures:             make(map[string]int),
		calls:                make(map[string]int),
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

// NewClientFactory returns an armpolicy client factory that sends all requests to this server.
// Retries are disabled so that injected failures surface immediately.
func (s *Server) NewClientFactory() (*armpolicy.ClientFactory, error) {
	opts := &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Transport: s,
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
	}

	cf, err := armpolicy.NewClientFactory("", credential{}, opts)
	if err != nil {
		return nil, fmt.Errorf("fakearm: creating client factory: %w", err)
	}

	return cf, nil
}

// Do implements [policy.Transporter].
func (s *Server) Do(req *http.Request) (*http.Response, error) {
	segs := strings.Split(strings.Trim(strings.ToLower(req.URL.Path), "/"), "/")
	// Expected: providers/microsoft.authorization/<type>/<name>[/versions].
	if len(segs) < minPathSegments || segs[0] != "providers" || segs[1] != "microsoft.authorization" {
		return jsonResponse(req, http.StatusNotFound, errorBody("PathNotFound", req.URL.Path))
	}

	defType, name := segs[2], segs[3]
	listVersions := len(segs) == versionsPathSegments && segs[4] == versionsSeg

	s.begin(name)
	defer s.end()

	if s.Latency > 0 {
		select {
		case <-req.Context().Done():
			return nil, fmt.Errorf("fakearm: %w", req.Context().Err())
		case <-time.After(s.Latency):
		}
	}

	s.mu.Lock()
	status, fail := s.failures[name]
	pd, pdOK := s.policyDefinitions[name]
	psd, psdOK := s.policySetDefinitions[name]
	s.mu.Unlock()

	if fail {
		return jsonResponse(req, status, errorBody("InjectedFailure", name))
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

func (s *Server) begin(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls[name]++
	s.totalCalls++
	s.inFlight++
	s.peakInFlight = max(s.peakInFlight, s.inFlight)
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

func policyDefinitionVersionList(name string, versions []string) map[string]any {
	value := make([]any, 0, len(versions))
	for _, v := range versions {
		value = append(value, map[string]any{
			"id":         fmt.Sprintf(policyDefinitionIDFmt+"/versions/%s", name, v),
			"name":       v,
			"type":       "Microsoft.Authorization/policyDefinitions/versions",
			"properties": policyDefinitionProperties(name, v),
		})
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
