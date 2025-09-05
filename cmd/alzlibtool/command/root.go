// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package command

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/alzlib/cmd/alzlibtool/command/check"
	"github.com/Azure/alzlib/cmd/alzlibtool/command/convert"
	"github.com/Azure/alzlib/cmd/alzlibtool/command/document"
	"github.com/Azure/alzlib/cmd/alzlibtool/command/generate"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	// commit holds the git commit hash injected at build time via ldflags.
	commit = ""
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:     "alzlibtool",
	Version: fmt.Sprintf("%s (commit: %s)", version, commit),
	Short:   "A cli tool for working with alzlib libraries",
	Long: `A cli tool for working with alzlib libraries.

This tool can:

- Convert policy definitions or policy set definitions from the source directory and write them to the destination
  directory.
- Perform operations and checks on an alzlib library member.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(&convert.ConvertBaseCmd)
	rootCmd.AddCommand(&check.CheckCmd)
	rootCmd.AddCommand(&document.DocumentBaseCmd)
	rootCmd.AddCommand(&generate.GenerateBaseCmd)
}
