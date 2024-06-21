// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/hashicorp/go-getter/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFullAlz tests the ALZ reference architecture creation in full.
func TestFullAlz(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	assert.NoError(t, err)
	az.AddPolicyClient(cf)
	dirfs, err := getRemoteLib(ctx)
	require.NoError(t, err)
	assert.NoError(t, az.Init(ctx, dirfs))
	h := deployment.NewHierarchy(az)
	err = h.FromArchitecture(ctx, "alz", "00000000-0000-0000-0000-000000000000", "testlocation")
	require.NoError(t, err)

	//assert.NoError(t, mg.GeneratePolicyAssignmentAdditionalRoleAssignments())
}

// TestInitMultiLib tests that we can initialize the library with multiple urls.
func TestInitMultiLib(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	az.Options.AllowOverwrite = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remoteLib, err := getRemoteLib(ctx)
	assert.NoError(t, err)
	dirfs := os.DirFS("../testdata/simple")
	err = az.Init(ctx, remoteLib, dirfs)
	assert.NoError(t, err)
	assert.Equal(t, 12, len(az.Archetypes()))
	// Test root archetype has been overridden
	arch, _ := az.Archetype("root")
	assert.Equal(t, 1, arch.PolicyDefinitions.Cardinality())
	arch, _ = az.Archetype("simpleo")
	assert.Equal(t, 1, arch.PolicyDefinitions.Cardinality())
	assert.Equal(t, 1, arch.PolicyAssignments.Cardinality())
}

// TestGoGetter.
func getRemoteLib(ctx context.Context) (fs.FS, error) {
	q := url.Values{}
	q.Add("depth", "1")
	q.Add("ref", "platform/alz/2024.03.03")
	u := "github.com/Azure/Azure-Landing-Zones-Library//platform/alz?" + q.Encode()
	dst := filepath.Join(".alzlib", "lib")
	client := getter.Client{}
	wd, _ := os.Getwd()
	_ = os.RemoveAll(dst)
	req := &getter.Request{
		Src: u,
		Dst: dst,
		Pwd: wd,
	}
	res, err := client.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	_ = res
	return os.DirFS(dst), nil
}
