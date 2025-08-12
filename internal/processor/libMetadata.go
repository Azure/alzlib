// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package processor

// LibMetadata represents the metadata of a library member in the ALZ Library.
type LibMetadata struct {
	Name        string `json:"name"         yaml:"name"`         // The name of the library member
	DisplayName string `json:"display_name" yaml:"display_name"` // The display name of the library member
	Description string `json:"description"  yaml:"description"`  // The description of the library member
	// The dependencies of the library member in the format of "path/tag", e.g. "platform/alz/2024.03.0
	Dependencies []LibMetadataDependency `json:"dependencies" yaml:"dependencies"`
	// The relative path to the library member, e.g. "platform/alz"
	Path string `json:"path" yaml:"path"`
}

// LibMetadataDependency represents a dependency of a library member.
// Use either Path + Ref or CustomUrl.
type LibMetadataDependency struct {
	// The relative path to the library member within the ALZ Library, e.g. "platform/alz"
	Path string `json:"path"       yaml:"path"`
	Ref  string `json:"ref"        yaml:"ref"` // The calver tag of the library member, e.g. "2024.03.0"
	// The custom URL (go-getter path) of the library member, used when the library member is not in the ALZ Library
	CustomURL string `json:"custom_url" yaml:"custom_url"`
}
