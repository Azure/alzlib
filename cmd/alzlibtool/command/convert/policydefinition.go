// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package convert

import (
	"os"

	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/internal/tools/checks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

const (
	// RequiredArgCount is the number of required arguments for convert commands.
	RequiredArgCount = 2
)

// policydefinitionCmd represents the policydefinition command.
var policydefinitionCmd = cobra.Command{
	Use:   "policydefinition [flags] sourceDir destDir",
	Short: "Convert policy definitions to the format required by alzlib.",
	Long:  `Reads policy definitions from the Enterprise-Scale repo and converts to the format required by alzlib.`,
	Args: cobra.MatchAll(
		cobra.ExactArgs(RequiredArgCount),
	),
	Run: func(cmd *cobra.Command, args []string) {
		valid := checker.NewValidator(checks.CheckResourceTypeIsCorrect)
		err := convertFiles[armpolicy.Definition](args[0], args[1], cmd, valid)
		if err != nil {
			cmd.PrintErrf("%s policy definintion conversion error: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
	},
}
