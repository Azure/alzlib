/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package command

import (
	"context"
	"os"

	"github.com/Azure/alzlib/cmd/alzlibtool/command/convert"
	"github.com/Azure/alzlib/cmd/alzlibtool/command/library"
	"github.com/spf13/cobra"
)

var version = "dev"

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:     "alzlibtool",
	Version: version,
	Short:   "A cli tool for working with alzlib libraries",
	Long: `A cli tool for working with alzlib libraries.

This tool can:

- Convert policy definitions or policy set definitions from the source directory and write them to the destination directory.
- Perform operations and checks on an alzlib library member.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(&convert.ConvertBaseCmd)
	rootCmd.AddCommand(&library.LibraryCmd)
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.essrctool.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
