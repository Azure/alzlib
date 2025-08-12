// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package convert

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

const (
	// directoryPermissions is the permission to use when creating directories.
	directoryPermissions = 0755
	// filePermissions is the permission to use when writing files.
	filePermissions = 0644
)

var convertCmdOverwrite bool

type convertible interface {
	armpolicy.Definition |
		armpolicy.SetDefinition
}

// ConvertBaseCmd represents the base process command.
var ConvertBaseCmd = cobra.Command{
	Use: "convert",
	Short: "Converts policy definitions or policy set definitions (depending on child command) " +
		"from the source directory and writes them to the destination directory.",
	Long: `Processes policy definitions or policy set definitions (depending on child command) ` +
		`from the source directory and writes them to the destination directory.
Required child arguments are the child command, and the source and destination directories.`,
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.PrintErrf("%s process command: missing required child command\n", cmd.ErrPrefix())
		cmd.Usage() // nolint: errcheck
		os.Exit(1)
	},
}

func init() {
	ConvertBaseCmd.PersistentFlags().
		BoolVarP(&convertCmdOverwrite, "overwrite", "o", false, "Overwrite existing files in the destination directory")
	ConvertBaseCmd.AddCommand(&policydefinitionCmd)
	ConvertBaseCmd.AddCommand(&policysetdefinitionCmd)
}

func convertFiles[C convertible](
	src, dst string,
	cmd *cobra.Command,
	valid checker.Validator,
) error {
	if _, err := os.ReadDir(dst); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(dst, directoryPermissions); err != nil {
				return fmt.Errorf("convert: error creating destination directory: %w", err)
			}
		} else {
			return fmt.Errorf("convert: error reading destination directory: %w", err)
		}
	}

	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error { //nolint:wrapcheck
		if err != nil {
			return err //nolint:wrapcheck
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		base := filepath.Base(path)

		baseNoExt := strings.TrimSuffix(base, filepath.Ext(base))
		if sovCloud := filepath.Ext(baseNoExt); sovCloud == ".AzureChinaCloud" ||
			sovCloud == ".AzureUSGovernment" {
			return nil
		}

		bytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("readFile error: '%s': %w", path, err)
		}

		resource := new(C)
		if err := json.Unmarshal(bytes, resource); err != nil {
			return fmt.Errorf("json.Ummarshal error: '%s', %w", path, err)
		}

		if err := valid.Validate(resource); err != nil {
			return fmt.Errorf("validation error: '%s', %w", path, err)
		}

		processedBytes := processResource(resource)
		destination := filepath.Join(dst, libraryFileName(resource))
		cmd.Printf("Processing %s => %s\n", path, destination)

		if _, err := os.Stat(destination); err == nil && !convertCmdOverwrite {
			return fmt.Errorf("destination file already exists and overwrite not set: '%s'", destination)
		}

		if err := os.WriteFile(destination, processedBytes, filePermissions); err != nil {
			return fmt.Errorf("error writing %s: %w", destination, err)
		}

		return nil
	})
}

func libraryFileName(in any) string {
	switch in := in.(type) {
	case *armpolicy.Definition:
		return fmt.Sprintf("%s.alz_policy_definition.json", *in.Name)
	case *armpolicy.SetDefinition:
		return fmt.Sprintf("%s.alz_policy_set_definition.json", *in.Name)
	default:
		return ""
	}
}

func processResource(resource any) []byte {
	jsonBytes, _ := json.MarshalIndent(resource, "", "  ")
	jsonBytes = removeArmFunctionEscaping(jsonBytes)

	return jsonBytes
}

func removeArmFunctionEscaping(in []byte) []byte {
	return regexp.MustCompile(`\"\[\[`).ReplaceAll(in, []byte(`"[`))
}
