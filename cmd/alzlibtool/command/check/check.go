// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package check

import (
	"github.com/spf13/cobra"
)

// CheckCmd represents the library check command.
var CheckCmd = cobra.Command{
	Use:   "check",
	Short: "Perform validaitons.",
	Long:  `Primarily used as a tool to check the validity of a library member and assets.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cmd.PrintErrf("%s library command: missing required child command\n", cmd.ErrPrefix())
		cmd.Usage() // nolint: errcheck
	},
}

func init() {
	CheckCmd.AddCommand(&libraryCmd)
}
