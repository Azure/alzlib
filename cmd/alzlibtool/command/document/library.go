package document

import (
	"os"

	"github.com/Azure/alzlib/pkg/doc"
	"github.com/spf13/cobra"
)

var documentLibraryBaseCmd = cobra.Command{
	Use:   "library path",
	Short: "Generates documentation for the supplied library path.",
	Long:  `Generates documentation for the supplied library path.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fs := os.DirFS(args[0])
		doc.AlzlibReadmeMd(cmd.Context(), os.Stdout, fs)
	},
}
