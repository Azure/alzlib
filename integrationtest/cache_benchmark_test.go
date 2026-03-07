// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"os"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/cache"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/alzlib/internal/auth"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azcorepolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

const (
	benchLibPath      = "./testdata/alzlib-2025-09-0"
	benchArchitecture = "alz"
	benchSubID        = "00000000-0000-0000-0000-000000000000"
	benchLocation     = "testlocation"
)

// BenchmarkFromArchitectureWithCache measures the time to initialize the library
// and build the full ALZ hierarchy using a pre-populated cache and no Azure client.
func BenchmarkFromArchitectureWithCache(b *testing.B) {
	f, err := os.Open(cacheFile)
	if os.IsNotExist(err) {
		b.Skipf("skipping: cache file %q not found", cacheFile)
	}

	if err != nil {
		b.Fatalf("opening cache file: %v", err)
	}

	defer f.Close()

	c, err := cache.NewCache(f)
	if err != nil {
		b.Fatalf("loading cache: %v", err)
	}

	b.ResetTimer()

	for b.Loop() {
		az := alzlib.NewAlzLib(nil)
		az.AddCache(c)

		ctx := context.Background()

		lib := alzlib.NewCustomLibraryReference(benchLibPath)
		if err := az.Init(ctx, lib); err != nil {
			b.Fatalf("Init: %v", err)
		}

		h := deployment.NewHierarchy(az)
		if err := h.FromArchitecture(ctx, benchArchitecture, benchSubID, benchLocation); err != nil {
			b.Fatalf("FromArchitecture: %v", err)
		}
	}
}

// BenchmarkFromArchitectureWithClient measures the time to initialize the library
// and build the full ALZ hierarchy by fetching built-in definitions from Azure.
// This benchmark requires valid Azure credentials.
// It runs exactly once (b.N = 1) to avoid hitting Azure API rate limits.
func BenchmarkFromArchitectureWithClient(b *testing.B) {
	tok, err := auth.NewToken()
	if err != nil {
		b.Skipf("skipping: could not obtain Azure credentials: %v", err)
	}

	cf, err := armpolicy.NewClientFactory("", tok, &arm.ClientOptions{
		ClientOptions: azcorepolicy.ClientOptions{
			Cloud: auth.GetCloudFromEnv(),
		},
	})
	if err != nil {
		b.Fatalf("creating policy client factory: %v", err)
	}

	az := alzlib.NewAlzLib(nil)
	az.AddPolicyClient(cf)

	ctx := context.Background()

	lib := alzlib.NewCustomLibraryReference(benchLibPath)

	b.ResetTimer()

	if err := az.Init(ctx, lib); err != nil {
		b.Fatalf("Init: %v", err)
	}

	h := deployment.NewHierarchy(az)
	if err := h.FromArchitecture(ctx, benchArchitecture, benchSubID, benchLocation); err != nil {
		b.Fatalf("FromArchitecture: %v", err)
	}
}
