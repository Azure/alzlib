package checks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Azure/alzlib/internal/processor"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/to"
	"github.com/hashicorp/go-multierror"
)

// libraryFileNameCheckModel is a model for checking library file names.
// It is used to unmarshal the JSON data from various types of library files.
type libraryFileNameCheckModel struct {
	Name       *string `json:"name,omitempty" yaml:"name,omitempty"`
	Properties *struct {
		Version *string `json:"version,omitempty" yaml:"version,omitempty"`
	}
}

func (m *libraryFileNameCheckModel) check(p libraryFileNameParts) error {
	if m.Name == nil || *m.Name != p.name {
		return fmt.Errorf("filename name component: expected %s, got %s", to.ValOrZero(m.Name), p.name)
	}

	if m.Properties == nil || m.Properties.Version == nil {
		if p.version != "" {
			return fmt.Errorf("filename version component: expected to be absent, got %s", p.version)
		}
		return nil
	}

	if *m.Properties.Version != p.version {
		return fmt.Errorf("filename version component: %s expected %s, got %s", *m.Name, to.ValOrZero(m.Properties.Version), p.version)
	}

	return nil
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

func (p *libraryFileNameParts) update(model *libraryFileNameCheckModel) {
	p.name = *model.Name
	if model.Properties != nil && model.Properties.Version != nil {
		p.version = *model.Properties.Version
	}
	if model.Properties == nil || model.Properties.Version == nil {
		p.version = ""
	}
}

type CheckLibraryFileNameOptions struct {
	Fix bool // Whether to rename files to match their internal name and version.
}

// CheckLibrary is a validator check that ensures all library file names are valid.
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

			nameErr := model.check(parts)
			if nameErr != nil {
				if opts.Fix {
					parts.update(model)
					fixes[filepath.Join(path, relPath)] = parts.String()
					return nil
				}

				if err := model.check(parts); err != nil {
					merr = multierror.Append(merr, err)
				}
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
	if len(split) < 3 {
		return parts, errors.New("invalid file name format")
	}
	parts.ext = split[len(split)-1]
	parts.fileType = split[len(split)-2]

	if len(split) > 3 {
		parts.version = strings.Join(split[1:len(split)-2], ".")
		parts.name = split[0]
		return parts, nil
	}

	parts.name = split[0]

	return parts, nil
}
