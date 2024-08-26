package alzlib

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/Azure/alzlib/internal/processor"
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

// FSs returns the filesystems of the library references, can be used with Alzlib.Init()
func (lr LibraryReferences) FSs() []fs.FS {
	fss := make([]fs.FS, len(lr))
	for i, l := range lr {
		fss[i] = l.FS()
	}
	return fss
}

// LibraryReference is an interface that represents a dependency of a library member.
// It can be fetched form either a custom go-getter URL or from the ALZ Library.
type LibraryReference interface {
	fmt.Stringer
	Fetch(ctx context.Context, desinationDirectory string) (fs.FS, error) // Fetch fetches the library member to the `.alzlib/destinationDirectory`. Override the base dir using `ALZLIB_DIR` env var.
	FS() fs.FS                                                            // FS returns the filesystem of the library member, can be used in Alzlib.Init()
}

var _ LibraryReference = (*AlzLibraryReference)(nil)
var _ LibraryReference = (*CustomLibraryReference)(nil)

// AlzLibraryReference is a struct that represents a dependency of a library member that is fetched from the ALZ Library.
type AlzLibraryReference struct {
	path       string
	ref        string
	filesystem fs.FS
}

func NewAlzLibraryReference(path, ref string) *AlzLibraryReference {
	return &AlzLibraryReference{
		path:       path,
		ref:        ref,
		filesystem: nil,
	}
}

// Fetch fetches the library member from the ALZ Library.
func (m *AlzLibraryReference) Fetch(ctx context.Context, destinationDirectory string) (fs.FS, error) {
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

func (m *AlzLibraryReference) Path() string {
	return m.path
}

func (m *AlzLibraryReference) Ref() string {
	return m.ref
}

// CustomLibraryReference is a struct that represents a dependency of a library member that is fetched from a custom go-getter URL.
type CustomLibraryReference struct {
	url        string
	filesystem fs.FS
}

func NewCustomLibraryReference(url string) *CustomLibraryReference {
	return &CustomLibraryReference{
		url:        url,
		filesystem: nil,
	}
}

// Fetch fetches the library member from the custom go-getter URL.
func (m *CustomLibraryReference) Fetch(ctx context.Context, destinationDirectory string) (fs.FS, error) {
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

func NewMetadataDependencyFromProcessor(in processor.LibMetadataDependency) LibraryReference {
	if in.CustomUrl != "" {
		return &CustomLibraryReference{
			url: in.CustomUrl,
		}
	}
	return &AlzLibraryReference{
		path: in.Path,
		ref:  in.Ref,
	}
}

func (m *Metadata) Name() string {
	return m.name
}

func (m *Metadata) DisplayName() string {
	return m.displayName
}

func (m *Metadata) Description() string {
	return m.description
}

func (m *Metadata) Dependencies() LibraryReferences {
	return m.dependencies
}

func (m *Metadata) Path() string {
	return m.path
}
