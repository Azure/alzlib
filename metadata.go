// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/Azure/alzlib/internal/processor"
)

const (
	// InitialLibraryReferencesCapacity is the initial capacity for library references slice.
	InitialLibraryReferencesCapacity = 5
)

// Metadata is a struct that represents the metadata of a library member.
type Metadata struct {
	name         string            // name of the library member
	displayName  string            // display name of the library member
	description  string            // description of the library member
	dependencies LibraryReferences // dependencies of the library member in the form of []LibraryReference
	path         string            // path of the library member within the ALZ Library
	ref          LibraryReference  // reference used to instantiate the library member
}

// LibraryReferences is a slice of LibraryReference.
// This type has methods for convenience.
type LibraryReferences []LibraryReference

// FSs returns the filesystems of the library references, can be used with Alzlib.Init().
func (m LibraryReferences) FSs() []fs.FS {
	fss := make([]fs.FS, len(m))
	for i, l := range m {
		fss[i] = l.FS()
	}

	return fss
}

// FetchWithDependencies recursively fetches all the library references and their dependencies.
// The destination directory a hash value that will be appended to the `.alzlib` directory in the
// current working
// directory unless overridden by the `ALZLIB_DIR` environment variable.
func (m LibraryReferences) FetchWithDependencies(ctx context.Context) (LibraryReferences, error) {
	processed := make(map[string]bool)
	result := make(LibraryReferences, 0, InitialLibraryReferencesCapacity)

	for _, lib := range m {
		err := fetchLibraryWithDependencies(ctx, processed, lib, &result)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// LibraryReference is an interface that represents a dependency of a library member.
// It can be fetched form either a custom go-getter URL or from the ALZ Library.
type LibraryReference interface {
	fmt.Stringer
	Fetch(
		ctx context.Context,
		desinationDirectory string,
	) (fs.FS, error) // Fetch fetches the library member to the `.alzlib/destinationDirectory`.
	// Override the base dir using `ALZLIB_DIR` env var.
	FetchWithDependencies(
		ctx context.Context,
	) (LibraryReferences, error) // FetchWithDependencies fetches the library member and its dependencies.
	FS() fs.FS // FS returns the filesystem of the library member, can be used in Alzlib.Init()
}

var (
	_ LibraryReference = (*AlzLibraryReference)(nil)
	_ LibraryReference = (*CustomLibraryReference)(nil)
)

// AlzLibraryReference is a struct that represents a dependency of a library member that is fetched
// from the ALZ
// Library.
type AlzLibraryReference struct {
	path       string
	ref        string
	filesystem fs.FS
}

// NewAlzLibraryReference creates a new AlzLibraryReference with the given path and ref.
func NewAlzLibraryReference(path, ref string) *AlzLibraryReference {
	return &AlzLibraryReference{
		path:       path,
		ref:        ref,
		filesystem: nil,
	}
}

// NewAlzLibraryReferenceFromString creates a new AlzLibraryReference by parsing
// a string in the form "<path>@<ref>" (the inverse of AlzLibraryReference.String()).
// Returns an error if s does not contain an "@" separator, has an empty path or
// has an empty ref.
func NewAlzLibraryReferenceFromString(s string) (*AlzLibraryReference, error) {
	idx := strings.LastIndex(s, "@")
	if idx <= 0 {
		return nil, fmt.Errorf(
			"NewAlzLibraryReferenceFromString: %q is not in the form <path>@<ref>", s,
		)
	}

	path := s[:idx]
	ref := s[idx+1:]

	if ref == "" {
		return nil, fmt.Errorf(
			"NewAlzLibraryReferenceFromString: %q has an empty ref", s,
		)
	}

	return NewAlzLibraryReference(path, ref), nil
}

// NewAlzLibraryReferenceFromFS creates a new AlzLibraryReference with the given path, ref and filesystem.
func NewAlzLibraryReferenceFromFS(path, ref string, filesystem fs.FS) *AlzLibraryReference {
	return &AlzLibraryReference{
		path:       path,
		ref:        ref,
		filesystem: filesystem,
	}
}

// Fetch fetches the library member from the ALZ Library.
func (m *AlzLibraryReference) Fetch(
	ctx context.Context,
	destinationDirectory string,
) (fs.FS, error) {
	if m.filesystem != nil {
		return m.filesystem, nil
	}

	f, err := FetchAzureLandingZonesLibraryMember(ctx, m.path, m.ref, destinationDirectory)
	if err != nil {
		return nil, fmt.Errorf("AlzLibraryReference.Fetch: could not fetch library member: %w", err)
	}

	m.filesystem = f

	return f, nil
}

// FS returns the filesystem of the library member.
func (m *AlzLibraryReference) FS() fs.FS {
	return m.filesystem
}

// String returns the formatted path and the tag of the library member.
func (m *AlzLibraryReference) String() string {
	return strings.Join([]string{m.path, m.ref}, "@")
}

// Path returns the path of the library member within the ALZ Library.
func (m *AlzLibraryReference) Path() string {
	return m.path
}

// Ref returns the reference of the library member.
func (m *AlzLibraryReference) Ref() string {
	return m.ref
}

// FetchWithDependencies fetches the library member and its dependencies.
// If you have more than one LibraryReference in a LibraryReferences slice, use
// LibraryReferences.FetchWithDependencies() instead.
func (m *AlzLibraryReference) FetchWithDependencies(
	ctx context.Context,
) (LibraryReferences, error) {
	processed := make(map[string]bool)
	result := make(LibraryReferences, 0, InitialLibraryReferencesCapacity)

	return result, fetchLibraryWithDependencies(ctx, processed, m, &result)
}

// CustomLibraryReference is a struct that represents a dependency of a library member that is
// fetched from a custom
// go-getter URL.
type CustomLibraryReference struct {
	url        string
	filesystem fs.FS
}

// NewCustomLibraryReference creates a new CustomLibraryReference with the given URL.
func NewCustomLibraryReference(url string) *CustomLibraryReference {
	return &CustomLibraryReference{
		url:        url,
		filesystem: nil,
	}
}

// NewCustomLibraryReferenceFromString creates a new CustomLibraryReference from
// a go-getter URL or local path string (the inverse of CustomLibraryReference.String()).
// It is equivalent to NewCustomLibraryReference and is provided for symmetry with
// NewAlzLibraryReferenceFromString.
func NewCustomLibraryReferenceFromString(s string) *CustomLibraryReference {
	return NewCustomLibraryReference(s)
}

// NewCustomLibraryReferenceFromFS creates a new CustomLibraryReference with the given URL and filesystem.
func NewCustomLibraryReferenceFromFS(url string, filesystem fs.FS) *CustomLibraryReference {
	return &CustomLibraryReference{
		url:        url,
		filesystem: filesystem,
	}
}

// Fetch fetches the library member from the custom go-getter URL.
func (m *CustomLibraryReference) Fetch(
	ctx context.Context,
	destinationDirectory string,
) (fs.FS, error) {
	if m.filesystem != nil {
		return m.filesystem, nil
	}

	f, err := FetchLibraryByGetterString(ctx, m.url, destinationDirectory)
	if err != nil {
		return nil, fmt.Errorf("CustomLibraryReference.Fetch: could not fetch library member: %w", err)
	}

	m.filesystem = f

	return f, nil
}

// FS returns the filesystem of the library member.
func (m *CustomLibraryReference) FS() fs.FS {
	return m.filesystem
}

// String returns the URL of the custom go-getter.
func (m *CustomLibraryReference) String() string {
	return m.url
}

// FetchWithDependencies fetches the library member and its dependencies.
// If you have more than one LibraryReference in a LibraryReferences slice, use
// LibraryReferences.FetchWithDependencies() instead.
func (m *CustomLibraryReference) FetchWithDependencies(
	ctx context.Context,
) (LibraryReferences, error) {
	processed := make(map[string]bool)
	result := make(LibraryReferences, 0, InitialLibraryReferencesCapacity)

	return result, fetchLibraryWithDependencies(ctx, processed, m, &result)
}

// NewMetadata creates a new Metadata instance from the processor.LibMetadata and a LibraryReference.
func NewMetadata(in *processor.LibMetadata, ref LibraryReference) *Metadata {
	dependencies := make([]LibraryReference, len(in.Dependencies))
	for i, dep := range in.Dependencies {
		dependencies[i] = NewMetadataDependencyFromProcessor(dep)
	}

	return &Metadata{
		name:         in.Name,
		displayName:  in.DisplayName,
		description:  in.Description,
		dependencies: dependencies,
		path:         in.Path,
		ref:          ref,
	}
}

// NewMetadataDependencyFromProcessor creates a LibraryReference from a processor.LibMetadataDependency.
func NewMetadataDependencyFromProcessor(in processor.LibMetadataDependency) LibraryReference {
	if in.CustomURL != "" {
		return &CustomLibraryReference{
			url: in.CustomURL,
		}
	}

	return &AlzLibraryReference{
		path: in.Path,
		ref:  in.Ref,
	}
}

// Name returns the name of the library member.
func (m *Metadata) Name() string {
	return m.name
}

// DisplayName returns the display name of the library member.
func (m *Metadata) DisplayName() string {
	return m.displayName
}

// Description returns the description of the library member.
func (m *Metadata) Description() string {
	return m.description
}

// Dependencies returns the dependencies of the library member.
func (m *Metadata) Dependencies() LibraryReferences {
	return m.dependencies
}

// Path returns the path of the library member within the ALZ Library.
func (m *Metadata) Path() string {
	return m.path
}

// IsAlzLibraryRef checks if the Metadata is an ALZ library reference.
func (m *Metadata) IsAlzLibraryRef() bool {
	_, ok := m.ref.(*AlzLibraryReference)
	return ok
}

// Ref returns the LibraryReference used to instantiate the library member.
func (m *Metadata) Ref() LibraryReference {
	return m.ref
}

// NewLibraryReference is a universal constructor that creates a LibraryReference
// from a string by detecting its form. Values that contain an "@" separator and
// do not look like a local filesystem path (i.e. do not start with ".", "/", "\"
// or a Windows drive letter such as "C:") are treated as ALZ Library references
// of the form "<path>@<ref>" and an *AlzLibraryReference is returned. Everything
// else is returned as a *CustomLibraryReference.
func NewLibraryReference(s string) LibraryReference {
	if !looksLikeLocalPath(s) {
		if ref, err := NewAlzLibraryReferenceFromString(s); err == nil {
			return ref
		}
	}

	return NewCustomLibraryReference(s)
}

// looksLikeLocalPath reports whether p has a prefix that indicates a local
// filesystem path rather than an ALZ Library member path.
func looksLikeLocalPath(p string) bool {
	if strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return true
	}
	// Windows drive letter, e.g. "C:" or "c:".
	if len(p) >= 2 && p[1] == ':' {
		c := p[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}

	return false
}
