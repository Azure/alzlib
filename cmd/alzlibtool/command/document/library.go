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

The generated documentation follows the current overwrite semantics: policy assignments, role
definitions, archetypes, architectures and policy default values are replaced in full by this
member's version. Policy definitions and policy set definitions are not, the dependency
version is kept. Duplicate archetype override names remain an error regardless of this flag.`,
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
				"Warning: generated documentation follows the existing overwrite semantics; " +
					"policy (set) definition redefinitions retain the dependency version, and " +
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
			"Document the library using the current overwrite semantics. Policy assignments, role "+
				"definitions, archetypes, architectures and policy default values are replaced in full, "+
				"not merged field by field. Policy (set) definitions keep the dependency version; for "+
				"those the flag only suppresses the duplicate error.")
}
