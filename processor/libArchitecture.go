package processor

// LibArchitecture represents a management group hierarchy in the library.
type LibArchitecture struct {
	Name             string `json:"name"`
	ManagementGroups []struct {
		Id          string   `json:"id"`
		DisplayName string   `json:"display_name"`
		Archetypes  []string `json:"archetypes"`
		ParentId    string   `json:"parent_id"`
		Exists      bool     `json:"exists"`
	}
}
