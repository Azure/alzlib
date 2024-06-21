// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
)

const (
	alzLibraryTag = "2024.03.03"
)

// Example_deploymentNewHierarchy tests the ALZ reference architecture creation in full.
func Example_deploymentNewHierarchy() {
	az := alzlib.NewAlzLib(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	if err != nil {
		fmt.Println(err)
	}
	az.AddPolicyClient(cf)
	dirfs, err := alzlib.FetchAzureLandingZonesByTag(ctx, alzLibraryTag)
	if err != nil {
		fmt.Println(err)
	}
	err = az.Init(ctx, dirfs)
	if err != nil {
		fmt.Println(err)
	}
	h := deployment.NewHierarchy(az)
	err = h.FromArchitecture(ctx, "alz", "00000000-0000-0000-0000-000000000000", "testlocation")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Management groups:", h.ManagementGroups())

	// Output:
	// Management groups: [online sandboxes platform management connectivity identity alzroot landingzones corp]
}

// TestInitMultiLib tests that we can initialize the library with multiple urls.
func TestInitMultiLib(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	az.Options.AllowOverwrite = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remoteLib, err := alzlib.FetchAzureLandingZonesByTag(ctx, alzLibraryTag)
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
