// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
	Long: `Generates documentation for the supplied library path.

Use --library-overwrite-enabled when this library member intentionally redefines assets that
are also provided by its dependencies. Without it, documentation generation fails during
library initialization with an "already exists in the library" error.

The generated documentation uses this member's version of redefined assets, replaced in full
rather than merged field by field. Policy definitions and policy set definitions are replaced
per version: a redefined version replaces the dependency's, other versions are kept.
Duplicate archetype override names remain an error regardless of this flag.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		thislib := alzlib.NewCustomLibraryReference(args[0])

		alllibs, err := thislib.FetchWithDependencies(cmd.Context())
		if err != nil {
			cmd.PrintErrf(
				"%s could not fetch all libraries with dependencies: %v\n",
				cmd.ErrPrefix(),
				err,
			)
			os.Exit(1)
		}

		libraryOverwriteEnabled, _ := cmd.Flags().GetBool("library-overwrite-enabled")

		opts := alzlib.NewAlzLib(nil).Options
		opts.AllowOverwrite = libraryOverwriteEnabled

		if libraryOverwriteEnabled {
			// stderr only, so the Markdown on stdout stays usable in a pipeline.
			cmd.PrintErrln(
				"Warning: redefined assets replace the dependency's in full, not field by field, and " +
					"duplicate archetype override names remain an error.")
		}

		err = doc.AlzlibReadmeMdWithOptions(cmd.Context(), os.Stdout, opts, alllibs...)
		if err != nil {
			cmd.PrintErrf("%s library documentation error: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
	},
}

func init() {
	documentLibraryBaseCmd.Flags().
		Bool(
			"library-overwrite-enabled", false,
			"Allow this library member to redefine assets provided by its dependencies. Redefined "+
				"assets are replaced in full, not merged field by field; policy (set) definitions are "+
				"replaced per version. Duplicate archetype override names remain an error.")
}
