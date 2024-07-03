// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package library

import (
	"github.com/spf13/cobra"
)

// LibraryCmd represents the policydefinition command.
var LibraryCmd = cobra.Command{
	Use:   "library [flags]",
	Short: "Perform operations on an alzlib library member.",
	Long:  `Primarily used a a tool to check the validity of a library member.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.PrintErrf("%s library command: missing required child command\n", cmd.ErrPrefix())
		cmd.Usage() // nolint: errcheck
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
