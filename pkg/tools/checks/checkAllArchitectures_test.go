// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"context"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAllArchitectures(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	ctx := context.Background()
	fs, err := alzlib.FetchAzureLandingZonesLibraryMember(ctx, "platform/alz", "2024.03.03", "0")
	require.NoError(t, err)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	require.NoError(t, err)
	az.AddPolicyClient(cf)
	require.NoError(t, err)
	require.NoError(t, az.Init(ctx, fs))
	assert.NoError(t, checkAllArchitectures(az))
}
