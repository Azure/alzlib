// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/alzlib/internal/processor"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/to"
)

func TestParseLibraryFileName(t *testing.T) {
	tests := []struct {
		name          string
		fileName      string
		expectedParts libraryFileNameParts
		expectError   bool
	}{
		{
			name:     "Valid file name with version",
			fileName: "mypol.1.0.0.alz_policy_definition.json",
			expectedParts: libraryFileNameParts{
				name:     "mypol",
				version:  "1.0.0",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
			expectError: false,
		},
		{
			name:     "Valid file name without version",
			fileName: "mypol.alz_policy_definition.json",
			expectedParts: libraryFileNameParts{
				name:     "mypol",
				version:  "",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
			expectError: false,
		},
		{
			name:     "Valid file name with complex version",
			fileName: "policy.2.1.3-beta-1.alz_policy_set_definition.yaml",
			expectedParts: libraryFileNameParts{
				name:     "policy",
				version:  "2.1.3-beta-1",
				fileType: "alz_policy_set_definition",
				ext:      "yaml",
			},
			expectError: false,
		},
		{
			name:     "Valid file name with archetype override",
			fileName: "root.1.2.3.alz_archetype_override.json",
			expectedParts: libraryFileNameParts{
				name:     "root",
				version:  "1.2.3",
				fileType: "alz_archetype_override",
				ext:      "json",
			},
			expectError: false,
		},
		{
			name:     "Valid file name with architecture definition",
			fileName: "my_arch.alz_architecture_definition.yaml",
			expectedParts: libraryFileNameParts{
				name:     "my_arch",
				version:  "",
				fileType: "alz_architecture_definition",
				ext:      "yaml",
			},
			expectError: false,
		},
		{
			name:     "Valid file name with policy assignment",
			fileName: "assignment.3.0.0.alz_policy_assignment.json",
			expectedParts: libraryFileNameParts{
				name:     "assignment",
				version:  "3.0.0",
				fileType: "alz_policy_assignment",
				ext:      "json",
			},
			expectError: false,
		},
		{
			name:     "Valid file name with role definition",
			fileName: "customrole.alz_role_definition.json",
			expectedParts: libraryFileNameParts{
				name:     "customrole",
				version:  "",
				fileType: "alz_role_definition",
				ext:      "json",
			},
			expectError: false,
		},
		{
			name:        "Invalid file name - too few parts",
			fileName:    "invalid.json",
			expectError: true,
		},
		{
			name:        "Invalid file name - only one part",
			fileName:    "invalid",
			expectError: true,
		},
		{
			name:        "Invalid file name - only two parts",
			fileName:    "name.ext",
			expectError: true,
		},
		{
			name:     "Valid file name with single version segment",
			fileName: "test.1.alz_policy_definition.json",
			expectedParts: libraryFileNameParts{
				name:     "test",
				version:  "1",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
			expectError: false,
		},
		{
			name:     "Valid file name with two version segments",
			fileName: "test.1.0.alz_policy_definition.json",
			expectedParts: libraryFileNameParts{
				name:     "test",
				version:  "1.0",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
			expectError: false,
		},
		{
			name:     "Valid file name with four version segments",
			fileName: "test.10.20.30.40.alz_policy_default_values.json",
			expectedParts: libraryFileNameParts{
				name:     "test",
				version:  "10.20.30.40",
				fileType: "alz_policy_default_values",
				ext:      "json",
			},
			expectError: false,
		},
		{
			name:     "Valid YAML extension",
			fileName: "policy.1.2.alz_policy_definition.yaml",
			expectedParts: libraryFileNameParts{
				name:     "policy",
				version:  "1.2",
				fileType: "alz_policy_definition",
				ext:      "yaml",
			},
			expectError: false,
		},
		{
			name:     "Valid archetype definition",
			fileName: "corporate.alz_archetype_definition.json",
			expectedParts: libraryFileNameParts{
				name:     "corporate",
				version:  "",
				fileType: "alz_archetype_definition",
				ext:      "json",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := parseLibraryFileName(tt.fileName)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error but got nil")
				}

				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if parts != tt.expectedParts {
				t.Errorf("Expected parts %+v but got %+v", tt.expectedParts, parts)
			}
		})
	}
}

func Test_libraryFileNameParts_update(t *testing.T) {
	tests := []struct {
		name          string
		initialParts  libraryFileNameParts
		model         *libraryFileNameCheckModel
		expectedParts libraryFileNameParts
	}{
		{
			name: "Update with name and version",
			initialParts: libraryFileNameParts{
				name:     "oldname",
				version:  "0.0.1",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
			model: &libraryFileNameCheckModel{
				Name: to.Ptr("newname"),
				Properties: &libraryFileNameCheckModelProperties{
					Version: to.Ptr("1.2.3"),
				},
			},
			expectedParts: libraryFileNameParts{
				name:     "newname",
				version:  "1.2.3",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
		},
		{
			name: "Update with name only - no properties",
			initialParts: libraryFileNameParts{
				name:     "oldname",
				version:  "1.0.0",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
			model: &libraryFileNameCheckModel{
				Name:       to.Ptr("newname"),
				Properties: nil,
			},
			expectedParts: libraryFileNameParts{
				name:     "newname",
				version:  "",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
		},
		{
			name: "Update with name only - nil version",
			initialParts: libraryFileNameParts{
				name:     "oldname",
				version:  "2.1.0",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
			model: &libraryFileNameCheckModel{
				Name: to.Ptr("newname"),
				Properties: &libraryFileNameCheckModelProperties{
					Version: nil,
				},
			},
			expectedParts: libraryFileNameParts{
				name:     "newname",
				version:  "",
				fileType: "alz_policy_definition",
				ext:      "json",
			},
		},
		{
			name: "Update from no version to version",
			initialParts: libraryFileNameParts{
				name:     "myname",
				version:  "",
				fileType: "alz_archetype_definition",
				ext:      "yaml",
			},
			model: &libraryFileNameCheckModel{
				Name: to.Ptr("newname"),
				Properties: &libraryFileNameCheckModelProperties{
					Version: to.Ptr("3.0.0"),
				},
			},
			expectedParts: libraryFileNameParts{
				name:     "newname",
				version:  "3.0.0",
				fileType: "alz_archetype_definition",
				ext:      "yaml",
			},
		},
		{
			name: "Update preserves fileType and ext",
			initialParts: libraryFileNameParts{
				name:     "original",
				version:  "1.0.0",
				fileType: "alz_role_definition",
				ext:      "yaml",
			},
			model: &libraryFileNameCheckModel{
				Name: to.Ptr("updated"),
				Properties: &libraryFileNameCheckModelProperties{
					Version: to.Ptr("2.0.0"),
				},
			},
			expectedParts: libraryFileNameParts{
				name:     "updated",
				version:  "2.0.0",
				fileType: "alz_role_definition",
				ext:      "yaml",
			},
		},
		{
			name: "Update with empty version string",
			initialParts: libraryFileNameParts{
				name:     "test",
				version:  "1.0.0",
				fileType: "alz_policy_assignment",
				ext:      "json",
			},
			model: &libraryFileNameCheckModel{
				Name: to.Ptr("test2"),
				Properties: &libraryFileNameCheckModelProperties{
					Version: to.Ptr(""),
				},
			},
			expectedParts: libraryFileNameParts{
				name:     "test2",
				version:  "",
				fileType: "alz_policy_assignment",
				ext:      "json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy of initialParts to avoid mutation affecting the test
			parts := tt.initialParts

			parts = parts.update(tt.model)

			if parts.name != tt.expectedParts.name {
				t.Errorf("Expected name %q but got %q", tt.expectedParts.name, parts.name)
			}

			if parts.version != tt.expectedParts.version {
				t.Errorf("Expected version %q but got %q", tt.expectedParts.version, parts.version)
			}

			if parts.fileType != tt.expectedParts.fileType {
				t.Errorf("Expected fileType %q but got %q", tt.expectedParts.fileType, parts.fileType)
			}

			if parts.ext != tt.expectedParts.ext {
				t.Errorf("Expected ext %q but got %q", tt.expectedParts.ext, parts.ext)
			}
		})
	}
}

func TestCheckTypeTbt(t *testing.T) {
	tests := []struct {
		name      string
		model     *libraryFileNameCheckModel
		parts     libraryFileNameParts
		expectErr string
	}{
		{
			name:  "type is required for policy definition when missing",
			model: &libraryFileNameCheckModel{},
			parts: libraryFileNameParts{
				fileType: processor.PolicyDefinitionFileType,
			},
			expectErr: "`.type` property is required for this file type",
		},
		{
			name:  "type is optional for archetype definition",
			model: &libraryFileNameCheckModel{},
			parts: libraryFileNameParts{
				fileType: processor.ArchetypeDefinitionFileType,
			},
		},
		{
			name: "unknown type returns error",
			model: &libraryFileNameCheckModel{
				Type: to.Ptr("Unknown.Type"),
			},
			parts: libraryFileNameParts{
				fileType: processor.PolicyDefinitionFileType,
			},
			expectErr: "unknown ARM type \"Unknown.Type\"",
		},
		{
			name: "type mismatch returns error",
			model: &libraryFileNameCheckModel{
				Type: to.Ptr("Microsoft.Authorization/policyDefinitions"),
			},
			parts: libraryFileNameParts{
				fileType: processor.PolicySetDefinitionFileType,
			},
			expectErr: fmt.Sprintf("expected type segment %q, got %q", processor.PolicyDefinitionFileType, processor.PolicySetDefinitionFileType),
		},
		{
			name: "matching type passes",
			model: &libraryFileNameCheckModel{
				Type: to.Ptr("Microsoft.Authorization/policyDefinitions"),
			},
			parts: libraryFileNameParts{
				fileType: processor.PolicyDefinitionFileType,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checker.NewValidator(checkType(tt.model, tt.parts)).Validate()
			if tt.expectErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectErr)
			}

			if !strings.Contains(err.Error(), tt.expectErr) {
				t.Fatalf("expected error containing %q, got %q", tt.expectErr, err.Error())
			}
		})
	}
}

func TestCheckNameTbt(t *testing.T) {
	tests := []struct {
		name      string
		model     *libraryFileNameCheckModel
		parts     libraryFileNameParts
		expectErr string
	}{
		{
			name: "role name overrides base name",
			model: &libraryFileNameCheckModel{
				Name: to.Ptr("base"),
				Properties: &libraryFileNameCheckModelProperties{
					RoleName: to.Ptr("role"),
				},
			},
			parts: libraryFileNameParts{name: "role"},
		},
		{
			name: "role name mismatch returns error",
			model: &libraryFileNameCheckModel{
				Properties: &libraryFileNameCheckModelProperties{
					RoleName: to.Ptr("role"),
				},
			},
			parts:     libraryFileNameParts{name: "other"},
			expectErr: "expected \"role\", got \"other\"",
		},
		{
			name:      "name is required when role name absent",
			model:     &libraryFileNameCheckModel{},
			parts:     libraryFileNameParts{name: "any"},
			expectErr: "`.name` property is required",
		},
		{
			name: "name mismatch returns error",
			model: &libraryFileNameCheckModel{
				Name: to.Ptr("expected"),
			},
			parts:     libraryFileNameParts{name: "actual"},
			expectErr: "expected name segment \"expected\", got \"actual\"",
		},
		{
			name: "matching name passes",
			model: &libraryFileNameCheckModel{
				Name: to.Ptr("expected"),
			},
			parts: libraryFileNameParts{name: "expected"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checker.NewValidator(checkName(tt.model, tt.parts)).Validate()
			if tt.expectErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectErr)
			}

			if !strings.Contains(err.Error(), tt.expectErr) {
				t.Fatalf("expected error containing %q, got %q", tt.expectErr, err.Error())
			}
		})
	}
}

func TestCheckVersionTbt(t *testing.T) {
	tests := []struct {
		name      string
		model     *libraryFileNameCheckModel
		parts     libraryFileNameParts
		expectErr string
	}{
		{
			name:  "missing type skips validation",
			model: &libraryFileNameCheckModel{},
			parts: libraryFileNameParts{version: "1.0.0"},
		},
		{
			name: "version not allowed for type",
			model: &libraryFileNameCheckModel{
				Type: to.Ptr("Microsoft.Authorization/roleDefinitions"),
			},
			parts:     libraryFileNameParts{version: "1.0.0"},
			expectErr: "version not allowed for type \"Microsoft.Authorization/roleDefinitions\"",
		},
		{
			name: "version allowed type without property rejects version segment",
			model: &libraryFileNameCheckModel{
				Type: to.Ptr("Microsoft.Authorization/policyDefinitions"),
			},
			parts:     libraryFileNameParts{version: "1.2.3"},
			expectErr: "version segment in file name not allowed when no version is specified in properties",
		},
		{
			name: "version mismatch returns error",
			model: &libraryFileNameCheckModel{
				Type: to.Ptr("Microsoft.Authorization/policyDefinitions"),
				Properties: &libraryFileNameCheckModelProperties{
					Version: to.Ptr("1.0.0"),
				},
			},
			parts:     libraryFileNameParts{version: "2.0.0"},
			expectErr: "expected version segment \"1.0.0\", got \"2.0.0\"",
		},
		{
			name: "matching version passes",
			model: &libraryFileNameCheckModel{
				Type: to.Ptr("Microsoft.Authorization/policySetDefinitions"),
				Properties: &libraryFileNameCheckModelProperties{
					Version: to.Ptr("2.1.0"),
				},
			},
			parts: libraryFileNameParts{version: "2.1.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checker.NewValidator(checkVersion(tt.model, tt.parts)).Validate()
			if tt.expectErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectErr)
			}

			if !strings.Contains(err.Error(), tt.expectErr) {
				t.Fatalf("expected error containing %q, got %q", tt.expectErr, err.Error())
			}
		})
	}
}
