// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package check

import (
	"os"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/tools/checker"
	"github.com/Azure/alzlib/internal/tools/checks"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

// libraryCmd represents the library check command.
var libraryCmd = cobra.Command{
	Use:   "library [flags] dir",
	Short: "Perform operations on an alzlib library member.",
	Long:  `Primarily used a a tool to check the validity of a library member.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		az := alzlib.NewAlzLib(nil)
		creds, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			cmd.PrintErrf("%s could not get Azure credential: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
		cf, err := armpolicy.NewClientFactory("", creds, nil)
		if err != nil {
			cmd.PrintErrf("%s could not create Azure policy client factory: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
		az.AddPolicyClient(cf)
		thisRef := alzlib.NewCustomLibraryReference(args[0])
		libs, err := thisRef.FetchWithDependencies(cmd.Context())
		if err != nil {
			cmd.PrintErrf(
				"%s could not fetch all libraries with dependencies: %v\n",
				cmd.ErrPrefix(),
				err,
			)
			os.Exit(1)
		}
		err = az.Init(cmd.Context(), libs...)
		if err != nil {
			cmd.PrintErrf("%s library init error: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		chk := checker.NewValidator(
			checks.CheckAllDefinitionsAreReferenced,
			checks.CheckAllArchitectures,
			checks.CheckLibraryMemberPath,
			checks.CheckDefaults,
		)
		err = chk.Validate(az)
		if err != nil {
			cmd.PrintErrf("%s library check error: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
	},
}
