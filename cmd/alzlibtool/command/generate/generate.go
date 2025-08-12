// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package generate

import (
	"os"

	"github.com/spf13/cobra"
)

// GenerateBaseCmd is the base command for generating deployment JSON.
var GenerateBaseCmd = cobra.Command{
	Use:   "generate",
	Short: "Generates deployment JSON for the specified subcommand.",
	Long:  `Generates deployment JSON for the specified subcommand. This enables deployment with a tool of your choosing.`,
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.PrintErrf("%s generate command: missing required child command\n", cmd.ErrPrefix())
		cmd.Usage() // nolint: errcheck
		os.Exit(1)
	},
}

func init() {
	GenerateBaseCmd.AddCommand(&generateArchitectureBaseCmd)
}
