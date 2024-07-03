/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package convert

import (
	"os"

	"github.com/Azure/alzlib/tools/checker"
	"github.com/Azure/alzlib/tools/checks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

// policysetdefinitionCmd represents the policysetdefinition command.
var policysetdefinitionCmd = cobra.Command{
	Use:   "policysetdefinition [flags] sourceDir destDir",
	Short: "Convert policy set definitions to the format required by alzlib.",
	Long:  `Reads policy set definitions from the Enterprise-Scale repo and converts to the format required by alzlib.`,
	Args: cobra.MatchAll(
		cobra.ExactArgs(2),
	),
	Run: func(cmd *cobra.Command, args []string) {
		valid := checker.NewValidator(checks.CheckResourceTypeIsCorrect)
		err := convertFiles[armpolicy.SetDefinition](args[0], args[1], cmd, valid)
		if err != nil {
			cmd.PrintErrf("%s policy definintion conversion error: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
	},
}

func init() {
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// policysetdefinitionCmd.PersistentFlags().String("foo", "", "A help for foo").

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// policysetdefinitionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle").
}
