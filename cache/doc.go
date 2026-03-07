// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Package cache provides a cache for built-in Azure policy definitions and policy set definitions.
// It can be used to avoid repeated Azure API calls during AlzLib initialization.
//
// The typical workflow is:
//
//  1. Create a cache from an Azure tenant using [NewCacheFromAzure].
//  2. Save the cache to a file using [Cache.Save].
//  3. Load the cache from the file using [NewCache].
//  4. Inject the cache into AlzLib using AlzLib.AddCache.
package cache
