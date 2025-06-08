package checks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Azure/alzlib/internal/processor"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/internal/tools/filename"
)

type FileNameErr struct {
	fileNameErrors []error
}

func (e *FileNameErr) Error() string {
	if len(e.fileNameErrors) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Incorrect file names found:\n")
	for _, v := range e.fileNameErrors {
		sb.WriteString("  - ")
		sb.WriteString(v.Error())
		sb.WriteString("\n")
	}
	return sb.String()
}

func NewFileNameErr(errs ...error) *FileNameErr {
	return &FileNameErr{
		fileNameErrors: errs,
	}
}

func (e *FileNameErr) Add(errs ...error) {
	for _, err := range errs {
		if err == nil {
			continue // Skip nil errors
		}
		e.fileNameErrors = append(e.fileNameErrors, err)
	}
}

func CheckAssetFileNames(inputs ...any) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"All assets are correctly named",
		func() error {
			if len(inputs) != 1 {
				return fmt.Errorf("checkAssetFileName: expected 1 input, got %d", len(inputs))
			}
			dir, ok := inputs[0].(string)
			if !ok || dir == "" {
				return fmt.Errorf("checkAssetFileName: expected a non-empty string input, got %T", inputs[0])
			}
			return checkAssetFileNames(dir)
		},
	)
}

func checkAssetFileNames(directory string) error {
	errs := NewFileNameErr()
	err := filepath.WalkDir(directory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("checkAssetFileName: error walking directory %s: %w", path, err)
		}
		if d.IsDir() {
			return nil // Skip directories
		}
		ext := filepath.Ext(path)
		if !slices.Contains(processor.SupportedFileExtensions, ext) {
			return nil
		}
		if !slices.Contains(processor.SupportedFileExtensions, filepath.Ext(path)) {
			return nil
		}
		bytes, err := os.ReadFile(path) // Ensure the file can be opened
		if err != nil {
			return fmt.Errorf("checkAssetFileName: error reading file %s: %w", path, err)
		}
		if err := filename.Check(path, bytes); err != nil {
			if !errors.Is(err, filename.ErrIncorrectFileName) {
				return fmt.Errorf("checkAssetFileName: error checking file name for %s: %w", path, err)
			}
			errs.Add(err)
			return nil
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("checkAssetFileName: error walking directory %s: %w", directory, err)
	}
	if errs.Error() != "" {
		return errs
	}
	return nil
}
