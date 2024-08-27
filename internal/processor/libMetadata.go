// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

type LibMetadata struct {
	Name         string                  `json:"name" yaml:"name"`                 // The name of the library member
	DisplayName  string                  `json:"display_name" yaml:"display_name"` // The display name of the library member
	Description  string                  `json:"description" yaml:"description"`   // The description of the library member
	Dependencies []LibMetadataDependency `json:"dependencies" yaml:"dependencies"` // The dependencies of the library member in the format of "path/tag", e.g. "platform/alz/2024.03.0
	Path         string                  `json:"path" yaml:"path"`                 // The relative path to the library member, e.g. "platform/alz"
}

// LibMetadataDependency represents a dependency of a library member.
// Use either Path + Ref or CustomUrl.
type LibMetadataDependency struct {
	Path      string `json:"path" yaml:"path"`             // The relative path to the library member within the ALZ Library, e.g. "platform/alz"
	Ref       string `json:"ref" yaml:"ref"`               // The calver tag of the library member, e.g. "2024.03.0"
	CustomUrl string `json:"custom_url" yaml:"custom_url"` // The custom URL (go-getter path) of the library member, used when the library member is not in the ALZ Library
}
