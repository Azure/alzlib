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

// NewToken creates a new Entra token credential.
// It uses well-known Terraform ARM environment variables to configure the token acquisition.
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
		// if env var is set only disable if we can definitively say we are not using the CLI
		b, err := strconv.ParseBool(cli)
		if err == nil {
			opts.UseAzureCLI = b
		}
	}

	opts.ClientId = getFirstSetEnvVar("ARM_CLIENT_ID", "AZURE_CLIENT_ID")
	opts.ClientIdFile = getFirstSetEnvVar("ARM_CLIENT_ID_FILE_PATH")
	opts.ClientSecret = getFirstSetEnvVar("ARM_CLIENT_SECRET", "AZURE_CLIENT_SECRET")
	opts.ClientSecretFile = getFirstSetEnvVar("ARM_CLIENT_SECRET_FILE_PATH")
	opts.TenantId = getFirstSetEnvVar("ARM_TENANT_ID", "AZURE_TENANT_ID")
	opts.ClientCertBase64 = getFirstSetEnvVar("ARM_CLIENT_CERTIFICATE")
	opts.ClientCertPassword = []byte(getFirstSetEnvVar("ARM_CLIENT_CERTIFICATE_PASSWORD"))
	opts.ClientCertPfxFile = getFirstSetEnvVar("ARM_CLIENT_CERTIFICATE_PATH")
	opts.OIDCRequestToken = getFirstSetEnvVar(
		"ARM_OIDC_REQUEST_TOKEN",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
		"SYSTEM_ACCESSTOKEN",
	)
	opts.OIDCRequestURL = getFirstSetEnvVar(
		"ARM_OIDC_REQUEST_URL",
		"ACTIONS_ID_TOKEN_REQUEST_URL",
		"SYSTEM_OIDCREQUESTURI",
	)
	opts.OIDCToken = getFirstSetEnvVar("ARM_OIDC_TOKEN")
	opts.OIDCTokenFile = getFirstSetEnvVar("ARM_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE")
	opts.ADOServiceConnectionId = getFirstSetEnvVar(
		"ARM_ADO_PIPELINE_SERVICE_CONNECTION_ID",
		"ARM_OIDC_AZURE_SERVICE_CONNECTION_ID",
		"AZURESUBSCRIPTION_SERVICE_CONNECTION_ID",
	)

	opts.UseMSI = updateBoolValueAnyTrue(opts.UseMSI, "ARM_USE_MSI")
	opts.UseOIDCToken = updateBoolValueAnyTrue(opts.UseOIDCToken, "ARM_USE_OIDC")
	opts.UseOIDCTokenRequest = updateBoolValueAnyTrue(opts.UseOIDCTokenRequest, "ARM_USE_OIDC")
	opts.UseOIDCTokenFile = updateBoolValueAnyTrue(opts.UseOIDCTokenFile, "ARM_USE_OIDC", "ARM_USE_AKS_WORKLOAD_IDENTITY")

	if opts.ClientSecret != "" || opts.ClientSecretFile != "" {
		opts.UseClientSecret = true
	}

	if opts.ClientCertBase64 != "" || opts.ClientCertPfxFile != "" {
		opts.UseClientCert = true
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

func updateBoolValueAnyTrue(current bool, vars ...string) bool {
	if current {
		return true
	}

	for _, v := range vars {
		if val := os.Getenv(v); val != "" {
			b, _ := strconv.ParseBool(val)
			if b {
				return true
			}
		}
	}

	return false
}
