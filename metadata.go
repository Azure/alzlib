package alzlib

import (
	"strings"

	"github.com/Azure/alzlib/processor"
)

type Metadata struct {
	name         string
	displayName  string
	description  string
	dependencies []*MetadataDependency
	path         string
}

type MetadataDependency struct {
	path string
	tag  string
}

func NewMetadata(in *processor.LibMetadata) *Metadata {
	dependencies := make([]*MetadataDependency, len(in.Dependencies))
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

func NewMetadataDependencyFromProcessor(in string) *MetadataDependency {
	inSplit := strings.Split(in, "/")
	if len(inSplit) != 3 {
		return nil
	}
	return &MetadataDependency{
		path: strings.ToLower(strings.Join(inSplit[:2], "/")),
		tag:  strings.ToLower(inSplit[2]),
	}
}

func (m *MetadataDependency) String() string {
	return strings.Join([]string{m.path, m.tag}, "@")
}

func (m *MetadataDependency) Path() string {
	return m.path
}

func (m *MetadataDependency) Tag() string {
	return m.tag
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

func (m *Metadata) Dependencies() []*MetadataDependency {
	return m.dependencies
}

func (m *Metadata) Path() string {
	return m.path
}
