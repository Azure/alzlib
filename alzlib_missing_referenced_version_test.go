// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"net/http"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy/fake"
	"github.com/stretchr/testify/require"
)

const (
	missingVersionSetName = "e3ec7e09-768c-4b64-882c-fcada3772047"
	missingVersionDefName = "98728c90-32c7-4049-8429-847dc0f4fe37"
)

// TestGetDefinitionsFromAzureReferencedDefinitionVersionNotFound covers Azure/Azure-Landing-Zones#4327.
// When neither the built-in version listing of a referenced policy definition nor the definition itself
// provides a version satisfying the constraint, an error that names the definition and the policy set
// must be returned instead of a panic.
func TestGetDefinitionsFromAzureReferencedDefinitionVersionNotFound(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		listed       []*armpolicy.DefinitionVersion
		wantVersions string
	}{
		{
			name:         "empty version list",
			listed:       nil,
			wantVersions: "Versions available: []",
		},
		{
			name: "only non-matching versions listed",
			listed: []*armpolicy.DefinitionVersion{
				newPolicyDefinitionVersion(missingVersionDefName, "2.0.0"),
			},
			wantVersions: "Versions available: [2.0.0]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			az := NewAlzLib(nil)
			az.AddPolicyClient(newMissingVersionPolicyClientFactory(t, tc.listed))

			setID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/" + missingVersionSetName)
			require.NoError(t, err)

			var getErr error

			require.NotPanics(t, func() {
				getErr = az.GetDefinitionsFromAzure(t.Context(), []BuiltInRequest{{ResourceID: setID}})
			})
			require.Error(t, getErr)
			require.ErrorContains(t, getErr, missingVersionDefName)
			require.ErrorContains(t, getErr, missingVersionSetName)
			require.ErrorContains(t, getErr, tc.wantVersions)
		})
	}
}

// newMissingVersionPolicyClientFactory returns a policy client factory backed by fakes. The built-in policy
// set references the policy definition with constraint `1.*.*`, listing the versions of that definition
// returns the supplied values, and the definition itself is not found.
func newMissingVersionPolicyClientFactory(
	t *testing.T,
	listed []*armpolicy.DefinitionVersion,
) *armpolicy.ClientFactory {
	t.Helper()

	srv := fake.ServerFactory{
		SetDefinitionsServer: fake.SetDefinitionsServer{
			GetBuiltIn: func(
				_ context.Context,
				name string,
				_ *armpolicy.SetDefinitionsClientGetBuiltInOptions,
			) (resp azfake.Responder[armpolicy.SetDefinitionsClientGetBuiltInResponse], errResp azfake.ErrorResponder) {
				resp.SetResponse(http.StatusOK, armpolicy.SetDefinitionsClientGetBuiltInResponse{
					SetDefinition: armpolicy.SetDefinition{
						ID:   to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/" + name),
						Name: to.Ptr(name),
						Properties: &armpolicy.SetDefinitionProperties{
							Description: to.Ptr("unit test policy set definition"),
							DisplayName: to.Ptr("Unit Test Policy Set Definition"),
							Version:     to.Ptr("1.8.0"),
							PolicyDefinitions: []*armpolicy.DefinitionReference{
								{
									PolicyDefinitionID: to.Ptr(
										"/providers/Microsoft.Authorization/policyDefinitions/" + missingVersionDefName,
									),
									DefinitionVersion: to.Ptr("1.*.*"),
								},
							},
						},
					},
				}, nil)

				return resp, errResp
			},
		},
		DefinitionVersionsServer: fake.DefinitionVersionsServer{
			NewListBuiltInPager: func(
				_ string,
				_ *armpolicy.DefinitionVersionsClientListBuiltInOptions,
			) (resp azfake.PagerResponder[armpolicy.DefinitionVersionsClientListBuiltInResponse]) {
				resp.AddPage(http.StatusOK, armpolicy.DefinitionVersionsClientListBuiltInResponse{
					DefinitionVersionListResult: armpolicy.DefinitionVersionListResult{Value: listed},
				}, nil)

				return resp
			},
		},
		DefinitionsServer: fake.DefinitionsServer{
			GetBuiltIn: func(
				_ context.Context,
				_ string,
				_ *armpolicy.DefinitionsClientGetBuiltInOptions,
			) (resp azfake.Responder[armpolicy.DefinitionsClientGetBuiltInResponse], errResp azfake.ErrorResponder) {
				errResp.SetResponseError(http.StatusNotFound, "PolicyDefinitionNotFound")

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
