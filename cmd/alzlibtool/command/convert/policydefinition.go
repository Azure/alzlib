// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package convert

import (
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

// policydefinitionCmd represents the policydefinition command.
var policydefinitionCmd = cobra.Command{
	Use:   "policydefinition [flags] sourceDir destDir",
	Short: "Convert policy definitions to the format required by alzlib.",
	Long:  `Reads policy definitions from the Enterprise-Scale repo and converts to the format required by alzlib.`,
	Args: cobra.MatchAll(
		cobra.ExactArgs(2),
	),
	Run: func(cmd *cobra.Command, args []string) {
		err := convertFiles[armpolicy.Definition](args[0], args[1], cmd)
		if err != nil {
			cmd.PrintErrf("%s policy definintion conversion error: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
	},
}
