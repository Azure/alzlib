// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package check

import (
	"os"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/tools/checker"
	"github.com/Azure/alzlib/tools/checks"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

// libraryCmd represents the policydefinition command.
var libraryCmd = cobra.Command{
	Use:   "library [flags] dir",
	Short: "Perform operations on an alzlib library member.",
	Long:  `Primarily used a a tool to check the validity of a library member.`,
	Run: func(cmd *cobra.Command, args []string) {
		az := alzlib.NewAlzLib(nil)
		dirFs := os.DirFS(args[0])
		creds, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			cmd.PrintErrf("%s could not get Azure credential: %v\n", cmd.ErrPrefix(), err)
		}
		cf, err := armpolicy.NewClientFactory("", creds, nil)
		if err != nil {
			cmd.PrintErrf("%s could not create Azure policy client factory: %v\n", cmd.ErrPrefix(), err)
		}
		az.AddPolicyClient(cf)
		err = az.Init(cmd.Context(), dirFs)
		if err != nil {
			cmd.PrintErrf("%s library init error: %v\n", cmd.ErrPrefix(), err)
		}

		chk := checker.NewValidator(
			checks.CheckAllDefinitionsAreReferenced,
			checks.CheckAllArchitectures,
		)
		err = chk.Validate(az)
		if err != nil {
			cmd.PrintErrf("%s library check error: %v\n", cmd.ErrPrefix(), err)
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
