// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Package alzlib provides the data structures needed to deploy Azure Landing Zones.
// It takes in fs.FS as input and returns a map of resources that can be used to deploy
// Azure Landing Zones of varying complexity.
//
// Internally the Azure SDK is used to store the resources in memory.
// It is up to the caller to transform this data into the required format for
// deployment.
package alzlib
