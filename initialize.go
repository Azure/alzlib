// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"

	"github.com/Azure/alzlib/internal/environment"
	"github.com/Azure/alzlib/internal/processor"
	"github.com/hashicorp/go-getter/v2"
)

// Instance is used to track the current instance ID.
// When set by the caller, it prevents collisions in the .alzlib directory.
var Instance atomic.Uint32

// fetchLibraryWithDependencies takes a library reference, fetches it, and then fetches all of its
// dependencies. The destination directory is an integer that will be appended to the `.alzlib`
// directory in the current working
// directory.
// This can be override by setting the `ALZLIB_DIR` environment variable.
// The `LibraryReferences` slice can be used to initialize the AlzLib instance.
func fetchLibraryWithDependencies(
	ctx context.Context,
	processed map[string]bool,
	lib LibraryReference,
	result *LibraryReferences,
) error {
	if processed[lib.String()] {
		return nil
	}

	f, err := lib.Fetch(ctx, hash(lib))
	if err != nil {
		return fmt.Errorf(
			"FetchLibraryWithDependencies: error fetching library %s: %w",
			lib.String(),
			err,
		)
	}

	pscl := processor.NewClient(f)

	libmeta, err := pscl.Metadata()
	if err != nil {
		return fmt.Errorf(
			"FetchLibraryWithDependencies: error getting metadata for library %s: %w",
			lib.String(),
			err,
		)
	}

	meta := NewMetadata(libmeta, lib)
	// for each dependency, recurse using this function
	for _, dep := range meta.Dependencies() {
		err = fetchLibraryWithDependencies(ctx, processed, dep, result)
		if err != nil {
			return fmt.Errorf(
				"FetchLibraryWithDependencies: error fetching dependencies for library %s: %w",
				lib.String(),
				err,
			)
		}
	}
	// add the current library reference to the list
	*result = append(*result, lib)
	processed[lib.String()] = true

	return nil
}

// hash returns the SHA224 hash of a fmt.Stringer, as a string.
func hash(s fmt.Stringer) string {
	return hashStr(s.String())
}

// hash returns the SHA224 hash of a string, as a string.
func hashStr(s string) string {
	return fmt.Sprintf("%x", sha256.Sum224([]byte(s)))
}

// FetchAzureLandingZonesLibraryMember is a convenience function to fetch the Azure Landing Zones
// library by member path
// and tag (ref).
// It calls FetchLibraryByGetterString with the appropriate URL.
// The destination directory will be appended to the `.alzlib` directory in the current working
// directory.
// This can be override by setting the `ALZLIB_DIR` environment variable.
// To fetch the ALZ reference, supply "platform/alz" as the member, with the tag (e.g. 2024.03.03).
func FetchAzureLandingZonesLibraryMember(
	ctx context.Context,
	path, ref, dstDir string,
) (fs.FS, error) {
	ref = fmt.Sprintf("%s/%s", path, ref)
	q := url.Values{}
	q.Add("ref", ref)

	gitURL := environment.AlzLibraryGitURL()

	u := fmt.Sprintf("git::%s//%s?%s", gitURL, path, q.Encode())

	return FetchLibraryByGetterString(ctx, u, dstDir)
}

// FetchLibraryByGetterString fetches a library from a URL using the go-getter library.
// The caller must supply a valid go-getter URL and a destination directory, which will be appended
// to
// the `.alzlib` directory in the current working directory.
// This can be override by setting the `ALZLIB_DIR` environment variable.
// It returns an fs.FS interface to the fetched library to be used in the AlzLib.Init() method.
func FetchLibraryByGetterString(ctx context.Context, getterString, dstDir string) (fs.FS, error) {
	baseDir := environment.AlzLibDir()
	instance := strconv.Itoa(int(Instance.Load()))
	dst := filepath.Join(baseDir, instance, dstDir)
	client := getter.Client{
		DisableSymlinks: true,
	}

	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("FetchLibraryByGetterString: error getting working directory: %w", err)
	}

	if err := os.RemoveAll(dst); err != nil {
		return nil, fmt.Errorf(
			"FetchLibraryByGetterString: error cleaning destination directory %s: %w",
			dst,
			err,
		)
	}

	req := &getter.Request{
		Src: getterString,
		Dst: dst,
		Pwd: wd,
	}

	_, err = client.Get(ctx, req)
	if err != nil {
		return nil, fmt.Errorf(
			"FetchLibraryByGetterString: error fetching library. source `%s`, destination `%s`, wd `%s`: %w",
			getterString,
			dst,
			wd,
			err,
		)
	}

	return os.DirFS(dst), nil
}
