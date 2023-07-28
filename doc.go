// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Package alzlib provides the data structures needed to deploy Azure Landing Zones.
// It contains the custom Azure policies and policy sets needed to deploy the
// reference architecture.
// It also gets the referenced built-in definitions from the Azure Policy service.
//
// Internally the Azure SDK is used to store the resources in memory.
// It is up to the caller to transform this data into the required format for
// deployment.
package alzlib
