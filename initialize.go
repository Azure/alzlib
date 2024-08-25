package alzlib

import (
	"context"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/Azure/alzlib/pkg/processor"
)

// FetchAllLibrariesWithDependencies takes a library reference, fetches it, and then fetches all of its dependencies.
// Example usage:
//
// ```go
// az := alzlib.NewAlzLib(nil)
// // ... ensure that clients are created and initialized
// // e.g. az.AddPolicyClient(myClientFactory)
// thisLib := NewCustomLibraryReference("path/to/library")
// libs, err := FetchAllLibrariesWithDependencies(ctx, ".alzlib", 0, thisLib, make(LibraryReferences, 0, 5))
// // ... handle error
//
// err = az.Init(ctx, libs.FSs()...)
// // ... handle error
// ```
func FetchAllLibrariesWithDependencies(ctx context.Context, baseDir string, i int, lib LibraryReference, libs LibraryReferences) (LibraryReferences, error) {
	dir := filepath.Join(baseDir, strconv.Itoa(i))
	f, err := lib.Fetch(ctx, dir)
	if err != nil {
		return nil, err
	}
	pscl := processor.NewProcessorClient(f)
	libmeta, err := pscl.Metadata()
	if err != nil {
		return nil, err
	}
	meta := NewMetadata(libmeta)
	// for each dependency, recurse using this function
	for _, dep := range meta.Dependencies() {
		i++
		libs, err = FetchAllLibrariesWithDependencies(ctx, baseDir, i, dep, libs)
		if err != nil {
			return nil, err
		}
	}
	// add the current library reference to the list
	return addLibraryReferenceToSlice(libs, lib), nil
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
