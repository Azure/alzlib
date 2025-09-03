// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
Package auth provides a small helper for creating an Azure Entra (azcore.TokenCredential)
using well-known Azure/Terraform environment variables and conventions.

It wraps the Entra auth helper (aztfauth) with sensible defaults and environment-driven
configuration so calling code can obtain a credential suitable for use with the Azure SDKs
without duplicating environment parsing logic.

Usage

	import "github.com/Azure/alzlib/internal/auth"

	cred, err := auth.NewToken()
	if err != nil {
	    // handle error
	}
	// use cred with Azure SDK clients that accept azcore.TokenCredential

# Environment variables

NewToken reads a variety of environment variables to determine the right credential flow
and configuration. Common variables include (but are not limited to):

- ARM_ENVIRONMENT, AZURE_ENVIRONMENT
- ARM_CLIENT_ID, AZURE_CLIENT_ID
- ARM_CLIENT_SECRET, AZURE_CLIENT_SECRET
- ARM_TENANT_ID, AZURE_TENANT_ID
- ARM_CLIENT_CERTIFICATE, ARM_CLIENT_CERTIFICATE_PASSWORD, ARM_CLIENT_CERTIFICATE_PATH
- ARM_OIDC_TOKEN, ARM_OIDC_TOKEN_FILE_PATH, AZURE_FEDERATED_TOKEN_FILE
- ARM_OIDC_REQUEST_TOKEN, ACTIONS_ID_TOKEN_REQUEST_TOKEN, SYSTEM_ACCESSTOKEN
- ARM_OIDC_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_URL, SYSTEM_OIDCREQUESTURI
- ARM_USE_CLI, ARM_USE_MSI, ARM_USE_OIDC, ARM_USE_AKS_WORKLOAD_IDENTITY
- ARM_ADO_PIPELINE_SERVICE_CONNECTION_ID, ARM_OIDC_AZURE_SERVICE_CONNECTION_ID, AZURESUBSCRIPTION_SERVICE_CONNECTION_ID

# Notes

  - Some variables accept file paths (e.g. *_FILE_PATH) so secrets can be supplied via files.
  - The package maps environment names ("public", "usgovernment", "china") to the
    corresponding Azure cloud configuration.
  - The helper favors non-interactive credential flows appropriate for CI/CD and automated
    scenarios; it will enable use of the Azure CLI by default but respects ARM_USE_CLI for
    explicit control.
*/
package auth
