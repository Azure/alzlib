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

	t.Log("Creating root management group")
	arch, err := az.CopyArchetype("root")
	assert.NoError(t, err)
	req := deployment.ManagementGroupAddRequest{
		Id:               "root",
		DisplayName:      "root",
		ParentId:         "external",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	depl := deployment.NewHierarchy(az)
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("root").GeneratePolicyAssignmentAdditionalRoleAssignments())

	t.Log("Creating landing_zones management group")
	arch, err = az.CopyArchetype("landing_zones")
	assert.NoError(t, err)
	req = deployment.ManagementGroupAddRequest{
		Id:               "landing_zones",
		DisplayName:      "landing_zones",
		ParentId:         "root",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("landing_zones").GeneratePolicyAssignmentAdditionalRoleAssignments())

	t.Log("Creating platform management group")
	arch, err = az.CopyArchetype("platform")
	assert.NoError(t, err)
	req = deployment.ManagementGroupAddRequest{
		Id:               "platform",
		DisplayName:      "platform",
		ParentId:         "root",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("platform").GeneratePolicyAssignmentAdditionalRoleAssignments())

	t.Log("Creating sandboxes management group")
	arch, err = az.CopyArchetype("sandboxes")
	assert.NoError(t, err)
	req = deployment.ManagementGroupAddRequest{
		Id:               "sandboxes",
		DisplayName:      "sandboxes",
		ParentId:         "root",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("sandboxes").GeneratePolicyAssignmentAdditionalRoleAssignments())

	t.Log("Creating management management group")
	arch, err = az.CopyArchetype("management")
	assert.NoError(t, err)
	req = deployment.ManagementGroupAddRequest{
		Id:               "management",
		DisplayName:      "management",
		ParentId:         "platform",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("management").GeneratePolicyAssignmentAdditionalRoleAssignments())

	t.Log("Creating identity management group")
	arch, err = az.CopyArchetype("identity")
	assert.NoError(t, err)
	req = deployment.ManagementGroupAddRequest{
		Id:               "identity",
		DisplayName:      "identity",
		ParentId:         "platform",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("identity").GeneratePolicyAssignmentAdditionalRoleAssignments())

	t.Log("Creating connectivity management group")
	arch, err = az.CopyArchetype("connectivity")
	assert.NoError(t, err)
	req = deployment.ManagementGroupAddRequest{
		Id:               "connectivity",
		DisplayName:      "connectivity",
		ParentId:         "platform",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("connectivity").GeneratePolicyAssignmentAdditionalRoleAssignments())

	t.Log("Creating corp management group")
	arch, err = az.CopyArchetype("corp")
	assert.NoError(t, err)
	req = deployment.ManagementGroupAddRequest{
		Id:               "corp",
		DisplayName:      "corp",
		ParentId:         "landing_zones",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("corp").GeneratePolicyAssignmentAdditionalRoleAssignments())

	t.Log("Creating online management group")
	arch, err = az.CopyArchetype("online")
	assert.NoError(t, err)
	req = deployment.ManagementGroupAddRequest{
		Id:               "online",
		DisplayName:      "online",
		ParentId:         "landing_zones",
		ParentIsExternal: false,
		Archetype:        arch,
	}
	assert.NoError(t, depl.AddManagementGroup(context.Background(), req))
	assert.NoError(t, depl.GetManagementGroup("online").GeneratePolicyAssignmentAdditionalRoleAssignments())
}

// TestInitMultiLib tests that we can initialize the library with multiple urls.
func TestInitMultiLib(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	az.Options.AllowOverwrite = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remoteLib, err := getRemoteLib(ctx)
	assert.NoError(t, err)
	dirfs := os.DirFS("./testdata/simple")
	err = az.Init(ctx, remoteLib, dirfs)
	assert.NoError(t, err)
	assert.Equal(t, 12, len(az.ListArchetypes()))
	// Test root archetype has been overridden
	arch, _ := az.CopyArchetype("root")
	assert.Equal(t, 1, arch.PolicyDefinitions.Cardinality())
	arch, _ = az.CopyArchetype("simpleo")
	assert.Equal(t, 1, arch.PolicyDefinitions.Cardinality())
	assert.Equal(t, 1, arch.PolicyAssignments.Cardinality())
}

// TestGoGetter.
func getRemoteLib(ctx context.Context) (fs.FS, error) {
	q := url.Values{}
	q.Add("depth", "1")
	q.Add("ref", "platform/alz/2024.03.00")
	u := "git::https://github.com/Azure/Azure-Landing-Zones-Library//platform/alz?" + q.Encode()
	dst := filepath.Join(".alzlib", "lib")
	client := getter.Client{}
	wd, _ := os.Getwd()
	req := &getter.Request{
		Src: u,
		Dst: dst,
		Pwd: wd,
	}
	if _, err := client.Get(ctx, req); err != nil {
		return nil, err
	}
	return os.DirFS(dst), nil
}
