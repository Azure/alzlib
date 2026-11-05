// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"fmt"
	"net/http"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/testutil/fakearm"
	"github.com/Azure/alzlib/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fetchTestArchitecture = "fetchtest"
	fetchTestPdIDFmt      = "/providers/Microsoft.Authorization/policyDefinitions/%s"
	fetchTestPsdIDFmt     = "/providers/Microsoft.Authorization/policySetDefinitions/%s"
)

// fetchTestArchitectureYAML has four management groups whose archetypes reference overlapping
// built-in definitions.
const fetchTestArchitectureYAML = `name: fetchtest
management_groups:
  - id: root
    display_name: root
    archetypes: [a]
    exists: false
    parent_id: null
  - id: child1
    display_name: child1
    archetypes: [b]
    exists: false
    parent_id: root
  - id: child2
    display_name: child2
    archetypes: [c]
    exists: false
    parent_id: root
  - id: grandchild
    display_name: grandchild
    archetypes: [a, c]
    exists: false
    parent_id: child1
`

func fetchTestArchetypeYAML(name string, assignments ...string) string {
	res := fmt.Sprintf("name: %s\npolicy_assignments:\n", name)
	for _, pa := range assignments {
		res += fmt.Sprintf("  - %s\n", pa)
	}

	return res + "policy_definitions: []\npolicy_set_definitions: []\nrole_definitions: []\n"
}

func fetchTestAssignmentJSON(name, definitionID string) string {
	return fmt.Sprintf(`{
  "name": %q,
  "type": "Microsoft.Authorization/policyAssignments",
  "apiVersion": "2022-06-01",
  "location": "${default_location}",
  "identity": {"type": "None"},
  "properties": {
    "displayName": %q,
    "description": %q,
    "enforcementMode": "Default",
    "notScopes": [],
    "parameters": {},
    "policyDefinitionId": %q,
    "scope": "/providers/Microsoft.Management/managementGroups/PLACEHOLDER"
  }
}`, name, name, name+" description", definitionID)
}

// newFetchTestHierarchy returns a hierarchy whose AlzLib is initialised from an in-memory library and
// fetches built-in definitions from a fake ARM server.
func newFetchTestHierarchy(t *testing.T, archetypeC []string, assignments map[string]string) (*Hierarchy, *fakearm.Server) {
	t.Helper()

	lib := fstest.MapFS{
		"fetchtest.alz_architecture_definition.yaml": {Data: []byte(fetchTestArchitectureYAML)},
		"a.alz_archetype_definition.yaml":            {Data: []byte(fetchTestArchetypeYAML("a", "pa-pd-1", "pa-psd-1"))},
		"b.alz_archetype_definition.yaml":            {Data: []byte(fetchTestArchetypeYAML("b", "pa-pd-2", "pa-psd-1"))},
		"c.alz_archetype_definition.yaml":            {Data: []byte(fetchTestArchetypeYAML("c", archetypeC...))},
	}

	for name, definitionID := range assignments {
		lib[name+".alz_policy_assignment.json"] = &fstest.MapFile{Data: []byte(fetchTestAssignmentJSON(name, definitionID))}
	}

	srv := fakearm.New()
	srv.Latency = 20 * time.Millisecond

	for _, pd := range []string{"pd-1", "pd-2", "pd-3", "pd-4", "pd-5"} {
		srv.AddPolicyDefinition(pd, "1.0.0")
	}

	srv.AddPolicySetDefinition("psd-1", []string{"1.0.0"},
		fakearm.Reference{Name: "pd-1", Version: to.Ptr("1.*.*")},
		fakearm.Reference{Name: "pd-4"},
		fakearm.Reference{Name: "pd-5"},
	)

	cf, err := srv.NewClientFactory()
	require.NoError(t, err)

	az := alzlib.NewAlzLib(nil)
	az.AddPolicyClient(cf)
	require.NoError(t, az.Init(t.Context(), alzlib.NewCustomLibraryReferenceFromFS("fetchtest", lib)))

	return NewHierarchy(az), srv
}

func fetchTestAssignments() map[string]string {
	return map[string]string{
		"pa-pd-1":  fmt.Sprintf(fetchTestPdIDFmt, "pd-1"),
		"pa-pd-2":  fmt.Sprintf(fetchTestPdIDFmt, "pd-2"),
		"pa-pd-3":  fmt.Sprintf(fetchTestPdIDFmt, "pd-3"),
		"pa-psd-1": fmt.Sprintf(fetchTestPsdIDFmt, "psd-1"),
	}
}

func TestFromArchitecturePrefetchesOnce(t *testing.T) {
	t.Parallel()

	h, srv := newFetchTestHierarchy(t, []string{"pa-pd-3", "pa-pd-1"}, fetchTestAssignments())

	require.NoError(t, h.FromArchitecture(t.Context(), fetchTestArchitecture, "external", eastUSLocation))

	assert.Equal(t, []string{"child1", "child2", "grandchild", "root"}, h.ManagementGroupNames())
	assert.Equal(t, map[string]int{"pd-1": 1, "pd-2": 1, "pd-3": 1, "pd-4": 1, "pd-5": 1, "psd-1": 1}, srv.AllCalls())
	assert.Greater(t, srv.PeakInFlight(), 1)
}

func TestFromArchitectureFetchErrorIsWrapped(t *testing.T) {
	t.Parallel()

	h, srv := newFetchTestHierarchy(t, []string{"pa-pd-3", "pa-pd-1"}, fetchTestAssignments())
	srv.FailDefinition("pd-3", http.StatusNotFound)

	err := h.FromArchitecture(t.Context(), fetchTestArchitecture, "external", eastUSLocation)
	require.Error(t, err)
	assert.Contains(
		t,
		err.Error(),
		"Hierarchy.FromArchitecture: getting policy definitions from Azure for architecture `fetchtest`",
	)
	assert.Contains(t, err.Error(), "pd-3")
	assert.Empty(t, h.ManagementGroupNames())
}

func TestFromArchitectureUnresolvableAssignmentErrorUnchanged(t *testing.T) {
	t.Parallel()

	assignments := fetchTestAssignments()
	assignments["pa-bad"] = "not-a-resource-id"

	h, srv := newFetchTestHierarchy(t, []string{"pa-pd-3", "pa-bad"}, assignments)

	err := h.FromArchitecture(t.Context(), fetchTestArchitecture, "external", eastUSLocation)
	require.Error(t, err)
	// The management group reported depends on the order in which recurseAddManagementGroup visits
	// children, which is not defined, so only the assignment is asserted.
	assert.Contains(
		t,
		err.Error(),
		"Hierarchy.AddManagementGroup: getting referenced policy definition resource ID "+
			"for policy assignment `pa-bad` in management group ",
	)
	assert.NotContains(t, err.Error(), "Hierarchy.FromArchitecture: getting policy definitions from Azure")
	// The resolvable definitions are still fetched once by the prefetch.
	assert.Equal(t, 1, srv.Calls("pd-3"))
}
