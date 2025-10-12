// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type definitionVersionPage struct {
	response armpolicy.DefinitionVersionsClientListBuiltInResponse
	err      error
}

type fakeDefinitionVersionsPager struct {
	pages []definitionVersionPage
	index int
}

func (p *fakeDefinitionVersionsPager) More() bool {
	return p.index < len(p.pages)
}

func (p *fakeDefinitionVersionsPager) NextPage(context.Context) (armpolicy.DefinitionVersionsClientListBuiltInResponse, error) {
	if !p.More() {
		return armpolicy.DefinitionVersionsClientListBuiltInResponse{}, errors.New("no more pages")
	}

	page := p.pages[p.index]
	p.index++

	return page.response, page.err
}

type setDefinitionVersionPage struct {
	response armpolicy.SetDefinitionVersionsClientListBuiltInResponse
	err      error
}

type fakeSetDefinitionVersionsPager struct {
	pages []setDefinitionVersionPage
	index int
}

func (p *fakeSetDefinitionVersionsPager) More() bool {
	return p.index < len(p.pages)
}

func (p *fakeSetDefinitionVersionsPager) NextPage(context.Context) (armpolicy.SetDefinitionVersionsClientListBuiltInResponse, error) {
	if !p.More() {
		return armpolicy.SetDefinitionVersionsClientListBuiltInResponse{}, errors.New("no more pages")
	}

	page := p.pages[p.index]
	p.index++

	return page.response, page.err
}

func TestCollectPolicyDefinitionVersionsSuccess(t *testing.T) {
	t.Parallel()

	resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/policyDef")
	require.NoError(t, err)

	pager := &fakeDefinitionVersionsPager{
		pages: []definitionVersionPage{
			{
				response: armpolicy.DefinitionVersionsClientListBuiltInResponse{
					DefinitionVersionListResult: armpolicy.DefinitionVersionListResult{
						Value: []*armpolicy.DefinitionVersion{
							newPolicyDefinitionVersion("policyDef", "1.0.0"),
						},
					},
				},
			},
			{
				response: armpolicy.DefinitionVersionsClientListBuiltInResponse{
					DefinitionVersionListResult: armpolicy.DefinitionVersionListResult{
						Value: []*armpolicy.DefinitionVersion{
							newPolicyDefinitionVersion("policyDef", "2.0.0"),
						},
					},
				},
			},
		},
	}

	az := NewAlzLib(nil)

	versions, err := az.collectPolicyDefinitionVersions(context.Background(), pager, BuiltInRequest{ResourceID: resID})
	require.NoError(t, err)
	require.NotNil(t, versions)
	require.Len(t, versions.Versions(), 2)

	v, err := versions.GetVersionStrict(to.Ptr("2.0.0"))
	require.NoError(t, err)
	require.NotNil(t, v.Properties)
	require.NotNil(t, v.Properties.Version)
	assert.Equal(t, "2.0.0", *v.Properties.Version)
}

func TestCollectPolicyDefinitionVersionsPagerError(t *testing.T) {
	t.Parallel()

	resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/policyDef")
	require.NoError(t, err)

	pager := &fakeDefinitionVersionsPager{
		pages: []definitionVersionPage{
			{
				err: errors.New("boom"),
			},
		},
	}

	az := NewAlzLib(nil)

	_, err = az.collectPolicyDefinitionVersions(context.Background(), pager, BuiltInRequest{ResourceID: resID, Version: to.Ptr("1.0.0")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "listing built-in policy definition versions")
}

func TestCollectPolicyDefinitionVersionsValidationError(t *testing.T) {
	t.Parallel()

	resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/policyDef")
	require.NoError(t, err)

	invalid := &armpolicy.DefinitionVersion{
		ID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/policyDef/versions/1.0.0"),
		Properties: &armpolicy.DefinitionVersionProperties{
			Version: to.Ptr("1.0.0"),
		},
	}

	pager := &fakeDefinitionVersionsPager{
		pages: []definitionVersionPage{
			{
				response: armpolicy.DefinitionVersionsClientListBuiltInResponse{
					DefinitionVersionListResult: armpolicy.DefinitionVersionListResult{
						Value: []*armpolicy.DefinitionVersion{invalid},
					},
				},
			},
		},
	}

	az := NewAlzLib(nil)

	_, err = az.collectPolicyDefinitionVersions(context.Background(), pager, BuiltInRequest{ResourceID: resID, Version: to.Ptr("1.0.0")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "validating built-in policy definition version")
}

func TestCollectPolicySetDefinitionVersionsSuccess(t *testing.T) {
	t.Parallel()

	resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/policySet")
	require.NoError(t, err)

	pager := &fakeSetDefinitionVersionsPager{
		pages: []setDefinitionVersionPage{
			{
				response: armpolicy.SetDefinitionVersionsClientListBuiltInResponse{
					SetDefinitionVersionListResult: armpolicy.SetDefinitionVersionListResult{
						Value: []*armpolicy.SetDefinitionVersion{
							newPolicySetDefinitionVersion("policySet", "1.0.0"),
						},
					},
				},
			},
			{
				response: armpolicy.SetDefinitionVersionsClientListBuiltInResponse{
					SetDefinitionVersionListResult: armpolicy.SetDefinitionVersionListResult{
						Value: []*armpolicy.SetDefinitionVersion{
							newPolicySetDefinitionVersion("policySet", "2.0.0"),
						},
					},
				},
			},
		},
	}

	az := NewAlzLib(nil)

	versions, err := az.collectPolicySetDefinitionVersions(context.Background(), pager, BuiltInRequest{ResourceID: resID})
	require.NoError(t, err)
	require.NotNil(t, versions)
	require.Len(t, versions.Versions(), 2)

	v, err := versions.GetVersionStrict(to.Ptr("1.0.0"))
	require.NoError(t, err)
	require.NotNil(t, v.Properties)
	require.NotNil(t, v.Properties.Version)
	assert.Equal(t, "1.0.0", *v.Properties.Version)
}

func TestCollectPolicySetDefinitionVersionsPagerError(t *testing.T) {
	t.Parallel()

	resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/policySet")
	require.NoError(t, err)

	pager := &fakeSetDefinitionVersionsPager{
		pages: []setDefinitionVersionPage{
			{
				err: errors.New("boom"),
			},
		},
	}

	az := NewAlzLib(nil)

	_, err = az.collectPolicySetDefinitionVersions(context.Background(), pager, BuiltInRequest{ResourceID: resID, Version: to.Ptr("1.0.0")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "listing built-in policy set definition versions")
}

func TestCollectPolicySetDefinitionVersionsValidationError(t *testing.T) {
	t.Parallel()

	resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/policySet")
	require.NoError(t, err)

	invalid := &armpolicy.SetDefinitionVersion{
		ID: to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/policySet/versions/1.0.0"),
		Properties: &armpolicy.SetDefinitionVersionProperties{
			PolicyDefinitions: []*armpolicy.DefinitionReference{},
			Version:           to.Ptr("1.0.0"),
		},
	}

	pager := &fakeSetDefinitionVersionsPager{
		pages: []setDefinitionVersionPage{
			{
				response: armpolicy.SetDefinitionVersionsClientListBuiltInResponse{
					SetDefinitionVersionListResult: armpolicy.SetDefinitionVersionListResult{
						Value: []*armpolicy.SetDefinitionVersion{invalid},
					},
				},
			},
		},
	}

	az := NewAlzLib(nil)

	_, err = az.collectPolicySetDefinitionVersions(context.Background(), pager, BuiltInRequest{ResourceID: resID, Version: to.Ptr("1.0.0")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "validating built-in policy set definition version")
}

func newPolicyDefinitionVersion(name, version string) *armpolicy.DefinitionVersion {
	id := fmt.Sprintf("/providers/Microsoft.Authorization/policyDefinitions/%s/versions/%s", name, version)
	description := "unit test policy definition"
	displayName := "Unit Test Policy Definition"
	mode := "all"

	return &armpolicy.DefinitionVersion{
		ID: to.Ptr(id),
		Properties: &armpolicy.DefinitionVersionProperties{
			Description: &description,
			DisplayName: &displayName,
			Metadata:    map[string]any{},
			Mode:        &mode,
			Parameters:  map[string]*armpolicy.ParameterDefinitionsValue{},
			PolicyRule:  map[string]any{},
			Version:     &version,
		},
	}
}

func newPolicySetDefinitionVersion(name, version string) *armpolicy.SetDefinitionVersion {
	id := fmt.Sprintf("/providers/Microsoft.Authorization/policySetDefinitions/%s/versions/%s", name, version)
	description := "unit test policy set definition"
	displayName := "Unit Test Policy Set Definition"

	return &armpolicy.SetDefinitionVersion{
		ID: to.Ptr(id),
		Properties: &armpolicy.SetDefinitionVersionProperties{
			Description:            &description,
			DisplayName:            &displayName,
			Metadata:               map[string]any{},
			Parameters:             map[string]*armpolicy.ParameterDefinitionsValue{},
			PolicyDefinitionGroups: []*armpolicy.DefinitionGroup{},
			PolicyDefinitions:      []*armpolicy.DefinitionReference{},
			Version:                &version,
		},
	}
}
