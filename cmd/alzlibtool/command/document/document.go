// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package document

import (
	"os"

	"github.com/spf13/cobra"
)

// DocumentBaseCmd is the base command for generating documentation.
var DocumentBaseCmd = cobra.Command{
	Use:   "document",
	Short: "Generates documentation for alzlib resources.",
	Long:  `Produces documentation for alzlib resources, currently only library members supported.`,
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.PrintErrf("%s document command: missing required child command\n", cmd.ErrPrefix())
		cmd.Usage() // nolint: errcheck
		os.Exit(1)
	},
}

func init() {
	DocumentBaseCmd.AddCommand(&documentLibraryBaseCmd)
}
