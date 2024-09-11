package generate

import (
	"os"

	"github.com/spf13/cobra"
)

var GenerateBaseCmd = cobra.Command{
	Use:   "generate",
	Short: "Generates deployment JSON for the specified subcommand.",
	Long:  `Generates deployment JSON for the specified subcommand. This enables deployment with a tool of your choosing.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.PrintErrf("%s generate command: missing required child command\n", cmd.ErrPrefix())
		cmd.Usage() // nolint: errcheck
		os.Exit(1)
	},
}

func init() {
	GenerateBaseCmd.AddCommand(&generateArchitectureBaseCmd)
}
