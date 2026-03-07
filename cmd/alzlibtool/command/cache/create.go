// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"log/slog"
	"os"

	"github.com/Azure/alzlib/cache"
	"github.com/Azure/alzlib/internal/auth"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

var createCmd = cobra.Command{
	Use:   "create",
	Short: "Create a cache file from Azure built-in definitions.",
	Long: `Scans an Azure tenant for all built-in policy definitions and policy set definitions
and writes them to a local cache file. Requires Azure credentials (e.g. az login).`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		outFile, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		creds, err := auth.NewToken()
		if err != nil {
			cmd.PrintErrf("%s could not get Azure credential: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		cf, err := armpolicy.NewClientFactory("", creds, &arm.ClientOptions{
			ClientOptions: policy.ClientOptions{
				Cloud: auth.GetCloudFromEnv(),
			},
		})
		if err != nil {
			cmd.PrintErrf("%s could not create Azure policy client factory: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		var logger *slog.Logger
		if verbose {
			logger = slog.New(slog.NewTextHandler(cmd.OutOrStdout(), &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))
		}

		cmd.Printf("Scanning Azure tenant for built-in definitions...\n")

		c, err := cache.NewCacheFromAzure(cmd.Context(), cf, logger)
		if err != nil {
			cmd.PrintErrf("%s could not create cache from Azure: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		f, err := os.Create(outFile)
		if err != nil {
			cmd.PrintErrf("%s could not create output file %s: %v\n", cmd.ErrPrefix(), outFile, err)
			os.Exit(1)
		}
		defer f.Close()

		if err := c.Save(f); err != nil {
			cmd.PrintErrf("%s could not write cache file: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		cmd.Printf("Cache written to %s\n", outFile)
		cmd.Printf("  Policy definitions:     %d names, %d total versions\n", c.PolicyDefinitionNames(), c.PolicyDefinitionCount())
		cmd.Printf("  Policy set definitions:  %d names, %d total versions\n", c.PolicySetDefinitionNames(), c.PolicySetDefinitionCount())
	},
}

func init() {
	createCmd.Flags().
		StringP("output", "o", "alzlib-cache.json.gz", "Path to the output cache file.")
	createCmd.Flags().
		BoolP("verbose", "v", false, "Display detailed progress during cache creation.")
}
