// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"fmt"
	"slices"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

const (
	alzLibraryTag    = "2024.03.03"
	alzLibraryMember = "platform/alz"
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
		return
	}
	az.AddPolicyClient(cf)
	dirfs, err := alzlib.FetchAzureLandingZonesLibraryMember(ctx, alzLibraryMember, alzLibraryTag, "alz")
	if err != nil {
		fmt.Println(err)
		return
	}
	err = az.Init(ctx, dirfs)
	if err != nil {
		fmt.Println(err)
		return
	}
	h := deployment.NewHierarchy(az)
	err = h.FromArchitecture(ctx, "alz", "00000000-0000-0000-0000-000000000000", "testlocation")
	if err != nil {
		fmt.Println(err)
	}
	mgs := h.ManagementGroupNames()
	slices.Sort(mgs)
	fmt.Println("Management groups:", mgs)

	// Output:
	// Management groups: [alzroot connectivity corp identity landingzones management online platform sandboxes]
}
