// Package environment contains the types and methods for fetching configuration from the local environment.
package environment

import "os"

const (
	fetchDefaultBaseDir    = ".alzlib"                                      // fetchDefaultBaseDir is the default base directory for fetching libraries.
	fetchDefaultBaseDirEnv = "ALZLIB_DIR"                                   // fetchDefaultBaseDirEnv is the environment variable to override the default base directory.
	alzLibraryGitUrl       = "github.com/Azure/Azure-Landing-Zones-Library" // alzLibraryGitUrl is the URL of the Azure Landing Zones Library.
	alzLibraryGitUrlEnv    = "ALZLIB_LIBRARY_GIT_URL"                       // alzLibraryGitUrlEnv is the environment variable to override the default git URL.
)

// AlzLibDir contents of the `ALZLIB_DIR` environment variable, or the default which is `.alzlib`.
func AlzLibDir() string {
	dir := fetchDefaultBaseDir
	if d := os.Getenv(fetchDefaultBaseDirEnv); d != "" {
		dir = d
	}
	return dir
}

// AlzLibraryGitUrl contents of the `ALZLIB_LIBRARY_GIT_URL` environment variable, or the default which is `github.com/Azure/Azure-Landing-Zones-Library`.
func AlzLibraryGitUrl() string {
	url := alzLibraryGitUrl
	if u := os.Getenv(alzLibraryGitUrlEnv); u != "" {
		url = u
	}
	return url
}
