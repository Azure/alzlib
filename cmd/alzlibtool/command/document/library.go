package document

import (
	"os"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/doc"
	"github.com/spf13/cobra"
)

var documentLibraryBaseCmd = cobra.Command{
	Use:   "library path",
	Short: "Generates documentation for the supplied library path.",
	Long:  `Generates documentation for the supplied library path.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		thislib := alzlib.NewCustomLibraryReference(args[0])
		alllibs, err := alzlib.FetchLibraryWithDependencies(cmd.Context(), 0, thislib, make(alzlib.LibraryReferences, 0, 5))
		if err != nil {
			cmd.PrintErrf("%s could not fetch all libraries with dependencies: %v\n", cmd.ErrPrefix(), err)
		}
		err = doc.AlzlibReadmeMd(cmd.Context(), os.Stdout, alllibs...)
		if err != nil {
			cmd.PrintErrf("%s library documentation error: %v\n", cmd.ErrPrefix(), err)
		}
	},
}
