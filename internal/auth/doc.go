// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package auth

import (
	"os"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/entrauth/aztfauth"
)

// environmentToCloud maps environment names to their corresponding cloud configurations.
var environmentToCloud = map[string]cloud.Configuration{
	"public":       cloud.AzurePublic,
	"usgovernment": cloud.AzureGovernment,
	"china":        cloud.AzureChina,
}

func NewToken() (azcore.TokenCredential, error) {
	cld := cloud.AzurePublic
	if env := getFirstSetEnvVar("ARM_ENVIRONMENT", "AZURE_ENVIRONMENT"); env != "" {
		if cfg, ok := environmentToCloud[env]; ok {
			cld = cfg
		}
	}

	opts := aztfauth.Option{
		UseAzureCLI: true,
		ClientOptions: azcore.ClientOptions{
			Cloud: cld,
		},
	}

	if cli := getFirstSetEnvVar("ARM_USE_CLI"); cli != "" {
		b, _ := strconv.ParseBool(cli)
		opts.UseAzureCLI = b
	}

	return aztfauth.NewCredential(opts)
}

func getFirstSetEnvVar(vars ...string) string {
	for _, v := range vars {
		if val := os.Getenv(v); val != "" {
			return val
		}
	}

	return ""
}
