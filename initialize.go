package alzlib

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/Azure/alzlib/internal/processor"
	"github.com/hashicorp/go-getter/v2"
)

const (
	fetchDefaultBaseDir    = ".alzlib"                                      // fetchDefaultBaseDir is the default base directory for fetching libraries.
	fetchDefaultBaseDirEnv = "ALZLIB_DIR"                                   // fetchDefaultBaseDirEnv is the environment variable to override the default base directory.
	alzLibraryGitUrl       = "github.com/Azure/Azure-Landing-Zones-Library" // alzLibraryGitUrl is the URL of the Azure Landing Zones Library.
	alzLibraryGitUrlEnv    = "ALZLIB_LIBRARY_GIT_URL"                       // alzLibraryGitUrlEnv is the environment variable to override the default git URL.
)

// FetchLibraryWithDependencies takes a library reference, fetches it, and then fetches all of its dependencies.
// The destination directory is an integer that will be appended to the `.alzlib` directory in the current working directory.
// This can be override by setting the `ALZLIB_DIR` environment variable.
//
// Example usage:
//
// ```go
// az := alzlib.NewAlzLib(nil)
// // ... ensure that clients are created and initialized
// // e.g. az.AddPolicyClient(myClientFactory)
// thisLib := NewCustomLibraryReference("path/to/library")
// libs, err := FetchLibraryWithDependencies(ctx, ".alzlib", 0, thisLib, make(LibraryReferences, 0, 5))
// // ... handle error
//
// err = az.Init(ctx, libs.FSs()...)
// // ... handle error
// ```
func FetchLibraryWithDependencies(ctx context.Context, i int, lib LibraryReference, libs LibraryReferences) (LibraryReferences, error) {
	f, err := lib.Fetch(ctx, strconv.Itoa(i))
	if err != nil {
		return nil, fmt.Errorf("FetchLibraryWithDependencies: error fetching library %s: %w", lib.String(), err)
	}
	pscl := processor.NewProcessorClient(f)
	libmeta, err := pscl.Metadata()
	if err != nil {
		return nil, fmt.Errorf("FetchLibraryWithDependencies: error getting metadata for library %s: %w", lib.String(), err)
	}
	meta := NewMetadata(libmeta, lib)
	// for each dependency, recurse using this function
	for _, dep := range meta.Dependencies() {
		i++
		libs, err = FetchLibraryWithDependencies(ctx, i, dep, libs)
		if err != nil {
			return nil, fmt.Errorf("FetchLibraryWithDependencies: error fetching dependencies for library %s: %w", lib.String(), err)
		}
	}
	// add the current library reference to the list
	return addLibraryReferenceToSlice(libs, lib), nil
}

// FetchAzureLandingZonesLibraryByTag is a convenience function to fetch the Azure Landing Zones library by member path and tag (ref).
// It calls FetchLibraryByGetterString with the appropriate URL.
// The destination directory will be appended to the `.alzlib` directory in the current working directory.
// This can be override by setting the `ALZLIB_DIR` environment variable.
// To fetch the ALZ reference, supply "platform/alz" as the member, with the tag (e.g. 2024.03.03).
func FetchAzureLandingZonesLibraryMember(ctx context.Context, path, ref, dstDir string) (fs.FS, error) {
	ref = fmt.Sprintf("%s/%s", path, ref)
	q := url.Values{}
	q.Add("ref", ref)

	gitUrl := os.Getenv(alzLibraryGitUrlEnv)
	if gitUrl == "" {
		gitUrl = alzLibraryGitUrl
	}

	u := fmt.Sprintf("git::%s//%s?%s", gitUrl, path, q.Encode())
	return FetchLibraryByGetterString(ctx, u, dstDir)
}

// FetchLibraryByGetterString fetches a library from a URL using the go-getter library.
// The caller must supply a valid go-getter URL and a destination directory, which will be appended to
// the `.alzlib` directory in the current working directory.
// This can be override by setting the `ALZLIB_DIR` environment variable.
// It returns an fs.FS interface to the fetched library to be used in the AlzLib.Init() method.
func FetchLibraryByGetterString(ctx context.Context, getterString, dstDir string) (fs.FS, error) {
	baseDir := os.Getenv(fetchDefaultBaseDirEnv)
	if baseDir == "" {
		baseDir = fetchDefaultBaseDir
	}
	dst := filepath.Join(baseDir, dstDir)
	client := getter.Client{}
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("FetchLibraryByGetterString: error getting working directory: %w", err)
	}
	if err := os.RemoveAll(dst); err != nil {
		return nil, fmt.Errorf("FetchLibraryByGetterString: error cleaning destination directory %s: %w", dst, err)
	}
	req := &getter.Request{
		Src: getterString,
		Dst: dst,
		Pwd: wd,
	}
	_, err = client.Get(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("FetchLibraryByGetterString: error fetching library. source `%s`, destination `%s`, wd `%s`: %w", getterString, dst, wd, err)
	}
	return os.DirFS(dst), nil
}

// addLibraryReferenceToSlice adds a library reference to a slice if it does not already exist.
func addLibraryReferenceToSlice(libs LibraryReferences, lib LibraryReference) LibraryReferences {
	if exists := slices.ContainsFunc(libs, func(l LibraryReference) bool {
		return l.String() == lib.String()
	}); exists {
		return libs
	}

	return append(libs, lib)
}
