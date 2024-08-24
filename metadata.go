package alzlib

import (
	"context"
	"io/fs"
	"strings"

	"github.com/Azure/alzlib/pkg/processor"
)

type Metadata struct {
	name         string
	displayName  string
	description  string
	dependencies []LibraryReference
	path         string
}

// LibraryReference is an interface that represents a dependency of a library member.
// It can be fetched form either a custom go-getter URL or from the ALZ Library.
type LibraryReference interface {
	Fetch(ctx context.Context, desinationDirectory string) (fs.FS, error)
}

var _ LibraryReference = (*AlzLibraryReference)(nil)
var _ LibraryReference = (*CustomLibraryReference)(nil)

// AlzLibraryReference is a struct that represents a dependency of a library member that is fetched from the ALZ Library.
type AlzLibraryReference struct {
	path string
	ref  string
}

func NewAlzLibraryReference(path, ref string) *AlzLibraryReference {
	return &AlzLibraryReference{
		path: path,
		ref:  ref,
	}
}

// Fetch fetches the library member from the ALZ Library.
func (m *AlzLibraryReference) Fetch(ctx context.Context, destinationDirectory string) (fs.FS, error) {
	return FetchAzureLandingZonesLibraryMember(ctx, destinationDirectory, m.path, m.ref)
}

// String returns the formatted path and the tag of the library member.
func (m *AlzLibraryReference) String() string {
	return strings.Join([]string{m.path, m.ref}, "@")
}

// CustomLibraryReference is a struct that represents a dependency of a library member that is fetched from a custom go-getter URL.
type CustomLibraryReference struct {
	url string
}

func NewCustomLibraryReference(url string) *CustomLibraryReference {
	return &CustomLibraryReference{
		url: url,
	}
}

// Fetch fetches the library member from the custom go-getter URL.
func (m *CustomLibraryReference) Fetch(ctx context.Context, destinationDirectory string) (fs.FS, error) {
	return FetchLibraryByGetterString(ctx, m.url, destinationDirectory)
}

// String returns the URL of the custom go-getter.
func (m *CustomLibraryReference) String() string {
	return m.url
}

func NewMetadata(in *processor.LibMetadata) *Metadata {
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

func (m *AlzLibraryReference) Path() string {
	return m.path
}

func (m *AlzLibraryReference) Tag() string {
	return m.ref
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

func (m *Metadata) Dependencies() []LibraryReference {
	return m.dependencies
}

func (m *Metadata) Path() string {
	return m.path
}
