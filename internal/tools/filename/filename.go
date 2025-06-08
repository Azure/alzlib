package filename

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Azure/alzlib/internal/processor"
)

const (
	armTypePolicyDefinition    = "Microsoft.Authorization/policyDefinitions"
	armTypePolicySetDefinition = "Microsoft.Authorization/policySetDefinitions"
	armTypePolicyAssignment    = "Microsoft.Authorization/policyAssignments"
	armTypeRoleDefinition      = "Microsoft.Authorization/roleDefinitions"
)

var armTypeToFileNameType = map[string]string{
	armTypePolicyAssignment:    processor.AlzPolicyAssignment,
	armTypePolicyDefinition:    processor.AlzPolicyDefinition,
	armTypePolicySetDefinition: processor.AlzPolicySetDefinition,
	armTypeRoleDefinition:      processor.AlzRoleDefinition,
}

var ErrIncorrectFileName = errors.New("incorrect file name format")

type checkFileNameType struct {
	Name *string `json:"name,omitempty"`
	Type *string `json:"type,omitempty"`
}

// Check validates the file name against the expected format based on the content.
func Check(fileName string, content []byte) error {
	if !slices.Contains(processor.SupportedFileExtensions, filepath.Ext(fileName)) {
		return nil
	}

	fileName = filepath.Base(fileName) // Ensure the filename is just the base name, not a full path
	fileNameSegments := strings.Split(fileName, ".")
	if len(fileNameSegments) < 2 {
		return fmt.Errorf("checkAssetFileName: invalid file name format `%s`, expected at least 2 segments", fileName)
	}

	// Get last but one segment (the type segment)
	assetFileNameType := fileNameSegments[len(fileNameSegments)-2]

	if !slices.Contains(processor.SupportedFileTypes, assetFileNameType) {
		// we don't care about this file type
		return nil
	}

	if assetFileNameType == processor.AlzPolicyDefaultValues {
		// we don't care about this file type
		return nil
	}

	correctFileName, err := Generate(assetFileNameType, content)
	if err != nil {
		return fmt.Errorf("checkAssetFileName: error generating correct file name: %w", err)
	}

	fileNameNoExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	if correctFileName != fileNameNoExt {
		return errors.Join(ErrIncorrectFileName, fmt.Errorf("`%s` should be `%s`", fileName, correctFileName))
	}
	return nil
}

// Generate generates the correct file name based on the content provided.
// We also need the file name type, e..g `alz_policy_definition` or `alz_role_definition`
// because non-ARM types do not have a type field in the content.
// It expects the content to be a JSON object with "name" and "type" fields.
// It will return a string without the file extension, which is determined by the "type" field.
func Generate(fileNameType string, content []byte) (string, error) {
	var chk checkFileNameType

	if !slices.Contains(processor.SupportedFileTypes, fileNameType) {
		return "", fmt.Errorf("checkAssetFileName: unsupported file name type `%s`, supported types are %v", fileNameType, processor.SupportedFileTypes)
	}

	err := json.Unmarshal(content, &chk)
	if err != nil {
		return "", fmt.Errorf("checkAssetFileName: error unmarshaling content: %w", err)
	}

	if chk.Name == nil {
		return "", fmt.Errorf("checkAssetFileName: missing name in content")
	}

	var correctFileName string
	var expectedType string

	if slices.Contains([]string{
		processor.AlzArchetypeDefinition,
		processor.AlzArchetypeOverride,
		processor.AlzArchitectureDefinition,
	}, fileNameType) {
		// For archetype and architecture definitions, we don't have a type field in the content.
		expectedType = fileNameType
	}

	// We should have a type field in the content for ARM types.
	if expectedType == "" {
		if chk.Type == nil {
			return "", fmt.Errorf("checkAssetFileName: missing type in content for file name type `%s`", fileNameType)
		}
		var ok bool
		expectedType, ok = armTypeToFileNameType[*chk.Type]
		if !ok {
			return "", fmt.Errorf("checkAssetFileName: unsupported type `%s` in content for file name type `%s`, supported types are %v", *chk.Type, fileNameType, armTypeToFileNameType)
		}
	}

	correctFileName = fmt.Sprintf("%s.%s", *chk.Name, expectedType)

	return correctFileName, nil
}
