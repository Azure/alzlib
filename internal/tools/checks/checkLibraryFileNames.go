// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Azure/alzlib/internal/processor"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/to"
	"github.com/hashicorp/go-multierror"
)

const (
	versionlessLibraryFileNameParts = 3 // name.type.ext (no version segment), e.g. myRoleDef.alz_role_definition.json
)

// libraryFileNameCheckModel is a model for checking library file names.
// It is used to unmarshal the JSON data from various types of library files.
type libraryFileNameCheckModel struct {
	Name       *string `json:"name,omitempty" yaml:"name,omitempty"`
	Type       *string `json:"type,omitempty" yaml:"type,omitempty"`
	Properties *libraryFileNameCheckModelProperties
}

type libraryFileNameCheckModelProperties struct {
	Version  *string `json:"version,omitempty" yaml:"version,omitempty"`
	RoleName *string `json:"roleName,omitempty" yaml:"roleName,omitempty"`
}

func (m *libraryFileNameCheckModel) check(p libraryFileNameParts) error {
	v := checker.NewValidatorQuiet(
		checkType(m, p),
		checkName(m, p),
		checkVersion(m, p),
	)

	return v.Validate()
}

type libraryFileNameParts struct {
	name     string
	version  string
	fileType string
	ext      string
}

func (p libraryFileNameParts) String() string {
	if p.version != "" {
		return fmt.Sprintf("%s.%s.%s.%s", p.name, p.version, p.fileType, p.ext)
	}

	return fmt.Sprintf("%s.%s.%s", p.name, p.fileType, p.ext)
}

func (p libraryFileNameParts) update(model *libraryFileNameCheckModel) libraryFileNameParts {
	p.name = *model.Name

	if model.Properties != nil && model.Properties.RoleName != nil {
		p.name = *model.Properties.RoleName
	}

	if model.Properties != nil && model.Properties.Version != nil {
		p.version = *model.Properties.Version
	}

	if model.Properties == nil || model.Properties.Version == nil {
		p.version = ""
	}

	return p
}

// CheckLibraryFileNameOptions are options for the CheckLibraryFileNames function.
type CheckLibraryFileNameOptions struct {
	Fix bool // Whether to rename files to match their internal name and version.
}

// CheckLibraryFileNames is a validator check that ensures all library file names are valid.
func CheckLibraryFileNames(path string, opts *CheckLibraryFileNameOptions) checker.ValidatorCheck {
	if opts == nil {
		opts = new(CheckLibraryFileNameOptions)
	}

	return checker.NewValidatorCheck(
		"All library file names are valid",
		checkLibraryFileNames(path, opts),
	)
}

func checkLibraryFileNames(path string, opts *CheckLibraryFileNameOptions) func() error {
	valids := []*regexp.Regexp{
		processor.ArchetypeDefinitionRegex,
		processor.ArchetypeOverrideRegex,
		processor.ArchitectureDefinitionRegex,
		processor.PolicyAssignmentRegex,
		processor.PolicyDefinitionRegex,
		processor.PolicySetDefinitionRegex,
		processor.RoleDefinitionRegex,
	}

	fixes := make(map[string]string)

	return func() error {
		// merr is used to collect filename errors that do not stop the walk.
		var merr error

		dirFs := os.DirFS(path)

		walkErr := fs.WalkDir(dirFs, ".", func(relPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("walkLibraryFunc: accessing path %s: %w", relPath, err)
			}

			if d.IsDir() {
				return nil
			}

			validFile := false

			for _, v := range valids {
				if !v.MatchString(d.Name()) {
					continue
				}

				validFile = true

				break
			}

			if !validFile {
				return nil
			}

			fileBytes, err := os.ReadFile(filepath.Join(path, relPath))
			if err != nil {
				return fmt.Errorf("walkLibraryFunc: failed to read file: %s: %w", relPath, err)
			}

			model := new(libraryFileNameCheckModel)
			if err := processor.NewUnmarshaler(fileBytes, filepath.Ext(relPath)).Unmarshal(&model); err != nil {
				return fmt.Errorf("walkLibraryFunc: failed to unmarshal file: %s: %w", relPath, err)
			}

			parts, err := parseLibraryFileName(relPath)
			if err != nil {
				return fmt.Errorf("walkLibraryFunc: invalid library file name format: %s: %w", relPath, err)
			}

			err = model.check(parts)
			if err != nil {
				if opts.Fix {
					newParts := parts.update(model)
					fixes[filepath.Join(path, relPath)] = newParts.String()

					return nil
				}

				merr = multierror.Append(merr, err)
			}

			return nil
		})
		if walkErr != nil {
			return walkErr
		}

		if len(fixes) > 0 {
			for oldPath, newName := range fixes {
				newPath := filepath.Join(filepath.Dir(oldPath), newName)
				if err := os.Rename(oldPath, newPath); err != nil {
					merr = multierror.Append(merr, fmt.Errorf("failed to rename %s to %s: %w", oldPath, newPath, err))
				}
			}
		}

		return merr
	}
}

func parseLibraryFileName(path string) (libraryFileNameParts, error) {
	var parts libraryFileNameParts

	split := strings.Split(filepath.Base(path), ".")
	if len(split) < versionlessLibraryFileNameParts {
		return parts, errors.New("invalid file name format")
	}

	parts.ext = split[len(split)-1]
	parts.fileType = split[len(split)-2]

	if len(split) > versionlessLibraryFileNameParts {
		parts.version = strings.Join(split[1:len(split)-2], ".")
		parts.name = split[0]

		return parts, nil
	}

	parts.name = split[0]

	return parts, nil
}

var armType2FileNameType = map[string]string{
	"microsoft.authorization/roledefinitions":      processor.RoleDefinitionFileType,
	"microsoft.authorization/policydefinitions":    processor.PolicyDefinitionFileType,
	"microsoft.authorization/policysetdefinitions": processor.PolicySetDefinitionFileType,
	"microsoft.authorization/policyassignments":    processor.PolicyAssignmentFileType,
}

func checkType(model *libraryFileNameCheckModel, parts libraryFileNameParts) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		fmt.Sprintf("File type matches internal type for %s", parts.String()),
		func() error {
			if model.Type == nil {
				typesMust := []string{
					processor.PolicyAssignmentFileType,
					processor.PolicyDefinitionFileType,
					processor.PolicySetDefinitionFileType,
					processor.RoleDefinitionFileType,
				}

				if slices.Contains(typesMust, parts.fileType) {
					return fmt.Errorf("%s: `.type` property is required for this file type", parts.String())
				}

				return nil
			}

			mappedType, ok := armType2FileNameType[strings.ToLower(*model.Type)]
			if !ok {
				return fmt.Errorf("%s: unknown ARM type %q", parts.String(), *model.Type)
			}

			if mappedType != parts.fileType {
				return fmt.Errorf("%s: expected type segment %q, got %q", parts.String(), mappedType, parts.fileType)
			}

			return nil
		},
	)
}

func checkName(model *libraryFileNameCheckModel, parts libraryFileNameParts) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		fmt.Sprintf("File name matches internal name for %s", parts.String()),
		func() error {
			if model.Properties != nil && model.Properties.RoleName != nil {
				if *model.Properties.RoleName != parts.name {
					return fmt.Errorf("%s: expected %q, got %q", parts.String(), *model.Properties.RoleName, parts.name)
				}

				return nil
			}

			if to.ValOrZero(model.Name) == "" {
				return fmt.Errorf("%s: `.name` property is required", parts.String())
			}

			if *model.Name != parts.name {
				return fmt.Errorf("%s: expected name segment %q, got %q", parts.String(), *model.Name, parts.name)
			}

			return nil
		},
	)
}

var versionAllowedArmTypes = []string{
	"microsoft.authorization/policydefinitions",
	"microsoft.authorization/policysetdefinitions",
}

func checkVersion(model *libraryFileNameCheckModel, parts libraryFileNameParts) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		fmt.Sprintf("File version matches internal version for %s", parts.String()),
		func() error {
			if model.Type == nil {
				return nil
			}

			if !slices.Contains(versionAllowedArmTypes, strings.ToLower(*model.Type)) {
				if parts.version != "" {
					return fmt.Errorf("%s: version not allowed for type %q", parts.String(), *model.Type)
				}
			}

			if model.Properties == nil || model.Properties.Version == nil {
				if parts.version != "" {
					return fmt.Errorf(
						"%s: version segment in file name not allowed when no version is specified in properties",
						parts.String(),
					)
				}

				return nil
			}

			if *model.Properties.Version != parts.version {
				return fmt.Errorf(
					"%s: expected version segment %q, got %q", parts.String(), *model.Properties.Version, parts.version,
				)
			}

			return nil
		},
	)
}
