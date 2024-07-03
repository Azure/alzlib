// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package library

import (
	"os"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/tools/checker"
	"github.com/Azure/alzlib/tools/checks"
	"github.com/spf13/cobra"
)

// CheckCmd represents the library check command.
var CheckCmd = cobra.Command{
	Use:   "check [flags] dir",
	Short: "Perform operations on an alzlib library member.",
	Long:  `Primarily used a a tool to check the validity of a library member.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		az := alzlib.NewAlzLib(nil)
		dirFs := os.DirFS(args[0])
		az.Init(cmd.Context(), dirFs)

		chk := checker.NewValidator(checks.CheckAllDefinitionsAreReferenced)
		err := chk.Validate(az)
		if err != nil {
			cmd.PrintErrf("%s library check error: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
	},
}
