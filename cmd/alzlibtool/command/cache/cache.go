// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"os"

	"github.com/spf13/cobra"
)

// CacheBaseCmd is the parent command for cache operations.
var CacheBaseCmd = cobra.Command{
	Use:   "cache",
	Short: "Manage built-in policy definition caches.",
	Long:  `Create and inspect caches of built-in Azure policy definitions and policy set definitions.`,
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.PrintErrf("%s cache command: missing required child command\n", cmd.ErrPrefix())
		cmd.Usage() // nolint: errcheck
		os.Exit(1)
	},
}

func init() {
	CacheBaseCmd.AddCommand(&createCmd)
	CacheBaseCmd.AddCommand(&infoCmd)
}
