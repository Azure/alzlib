// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package environment

import (
	"os"
	"strconv"
)

const (
	// fetchDefaultBaseDir is the default base directory for fetching libraries.
	fetchDefaultBaseDir = ".alzlib"
	// fetchDefaultBaseDirEnv is the environment variable to override the default base directory.
	fetchDefaultBaseDirEnv = "ALZLIB_DIR"
	// alzLibraryGitURL is the URL of the Azure Landing Zones Library.
	alzLibraryGitURL = "github.com/Azure/Azure-Landing-Zones-Library"
	// alzLibraryGitURLEnv is the environment variable to override the default git URL.
	alzLibraryGitURLEnv = "ALZLIB_LIBRARY_GIT_URL"
	// libraryStoreEnabledEnv is the environment variable that enables the library store.
	libraryStoreEnabledEnv = "ALZLIB_LIBRARY_STORE_ENABLED"
)

// AlzLibDir contents of the `ALZLIB_DIR` environment variable, or the default which is `.alzlib`.
func AlzLibDir() string {
	dir := fetchDefaultBaseDir
	if d := os.Getenv(fetchDefaultBaseDirEnv); d != "" {
		dir = d
	}

	return dir
}

// AlzLibraryGitURL contents of the `ALZLIB_LIBRARY_GIT_URL` environment variable, or the default
// which is
// `github.com/Azure/Azure-Landing-Zones-Library`.
func AlzLibraryGitURL() string {
	url := alzLibraryGitURL
	if u := os.Getenv(alzLibraryGitURLEnv); u != "" {
		url = u
	}

	return url
}

// LibraryStoreEnabled reports whether the `ALZLIB_LIBRARY_STORE_ENABLED` environment variable is set
// to a true value, as accepted by strconv.ParseBool (for example `true` or `1`).
// It returns false when the variable is not set or is not a boolean.
func LibraryStoreEnabled() bool {
	enabled, err := strconv.ParseBool(os.Getenv(libraryStoreEnabledEnv))

	return err == nil && enabled
}
