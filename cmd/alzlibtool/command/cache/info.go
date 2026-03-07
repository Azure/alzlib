// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"os"
	"strings"

	"github.com/Azure/alzlib/cache"
	"github.com/spf13/cobra"
)

var infoCmd = cobra.Command{
	Use:   "info [flags] file",
	Short: "Display information about a cache file.",
	Long:  `Reads a cache file and displays summary statistics about the cached definitions.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		f, err := os.Open(args[0])
		if err != nil {
			cmd.PrintErrf("%s could not open cache file %s: %v\n", cmd.ErrPrefix(), args[0], err)
			os.Exit(1)
		}
		defer f.Close()

		c, err := cache.NewCache(f)
		if err != nil {
			cmd.PrintErrf("%s could not load cache file %s: %v\n", cmd.ErrPrefix(), args[0], err)
			os.Exit(1)
		}

		cmd.Printf("Cache file: %s\n", args[0])
		cmd.Printf("Policy definitions:     %d names, %d total versions\n", c.PolicyDefinitionNames(), c.PolicyDefinitionCount())
		cmd.Printf("Policy set definitions:  %d names, %d total versions\n", c.PolicySetDefinitionNames(), c.PolicySetDefinitionCount())

		verbose, _ := cmd.Flags().GetBool("verbose")
		if !verbose {
			return
		}

		cmd.Println()
		cmd.Println("Policy definitions:")

		for name, pdvs := range c.PolicyDefinitions() {
			versions := pdvs.Versions()
			if len(versions) == 0 {
				cmd.Printf("  %s (versionless)\n", name)
			} else {
				verStrs := make([]string, len(versions))
				for i, v := range versions {
					verStrs[i] = v.String()
				}

				cmd.Printf("  %s (%s)\n", name, strings.Join(verStrs, ", "))
			}
		}

		cmd.Println()
		cmd.Println("Policy set definitions:")

		for name, psdvs := range c.PolicySetDefinitions() {
			versions := psdvs.Versions()
			if len(versions) == 0 {
				cmd.Printf("  %s (versionless)\n", name)
			} else {
				verStrs := make([]string, len(versions))
				for i, v := range versions {
					verStrs[i] = v.String()
				}

				cmd.Printf("  %s (%s)\n", name, strings.Join(verStrs, ", "))
			}
		}
	},
}

func init() {
	infoCmd.Flags().
		BoolP("verbose", "v", false, "Display the name and versions of each cached definition.")
}
