package document

import (
	"os"

	"github.com/spf13/cobra"
)

var DocumentBaseCmd = cobra.Command{
	Use:   "document",
	Short: "Generates documentation for alzlib resources.",
	Long:  `Produces documentation for alzlib resourcesm, curreltly only library members supported.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.PrintErrf("%s document command: missing required child command\n", cmd.ErrPrefix())
		cmd.Usage() // nolint: errcheck
		os.Exit(1)
	},
}

func init() {
	DocumentBaseCmd.AddCommand(&documentLibraryBaseCmd)
}
