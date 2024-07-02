/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package convert

import (
	"os"

	"github.com/Azure/alzlib/tools/checker"
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
		valid := checker.NewValidator(checker.CheckResourceType)
		err := convertFiles[armpolicy.Definition](args[0], args[1], cmd, valid)
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
	// policydefinitionCmd.PersistentFlags().String("foo", "", "A help for foo").

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// policydefinitionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle").
}
