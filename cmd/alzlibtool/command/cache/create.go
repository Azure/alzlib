// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"log/slog"
	"os"
	"strings"

	alzlib "github.com/Azure/alzlib"
	"github.com/Azure/alzlib/cache"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/alzlib/internal/auth"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

const (
	// defaultRootMgID is the placeholder management group ID used when none is supplied.
	defaultRootMgID = "00000000-0000-0000-0000-000000000000"
	// defaultLocation is the default Azure location for architecture processing.
	defaultLocation = "northeurope"
)

var createCmd = cobra.Command{
	Use:   "create",
	Short: "Create a cache file from Azure built-in definitions.",
	Long: `Creates a cache of Azure built-in policy definitions and policy set definitions.

By default, the full set of Azure built-in definitions is scanned from the tenant and written
to the output file. Requires Azure credentials (e.g. az login).

When --library and --architecture are specified, only the definitions referenced by that
architecture are included, producing a smaller, use-case-specific cache. This is useful for
embedding the minimal set of definitions needed for a given deployment workflow.

A --library value may be either a local path (e.g. ./mylib) or an ALZ Library reference in
the form <member>@<ref>, e.g. platform/alz@2026.01.3. The flag may be specified multiple
times to combine several libraries; their dependencies are fetched recursively.

Use --library-overwrite-enabled to allow later libraries to overwrite definitions, policy
assignments, role definitions, archetypes and architectures already provided by earlier
libraries. This is useful when layering a custom library on top of a base ALZ library.

Use --from-cache to seed from an existing cache file (requires --library and --architecture).
Definitions already present in the seed cache are used directly and not re-fetched from Azure,
reducing the number of API calls. The same file may be used for both --from-cache and --output
to update a cache in-place.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		outFile, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")
		libraryRefs, _ := cmd.Flags().GetStringArray("library")
		architectureName, _ := cmd.Flags().GetString("architecture")
		fromCacheFile, _ := cmd.Flags().GetString("from-cache")
		libraryOverwriteEnabled, _ := cmd.Flags().GetBool("library-overwrite-enabled")

		// --library and --architecture must be specified together.
		if (len(libraryRefs) == 0) != (architectureName == "") {
			cmd.PrintErrf(
				"%s --library and --architecture must be specified together\n",
				cmd.ErrPrefix(),
			)
			os.Exit(1)
		}

		// --from-cache only makes sense in architecture-scoped mode where the
		// lazy cache-first lookup can skip individual Azure API calls. In full-scan
		// mode the bulk listing APIs fetch everything regardless, so a seed cache
		// cannot reduce work.
		if fromCacheFile != "" && len(libraryRefs) == 0 {
			cmd.PrintErrf(
				"%s --from-cache requires --library and --architecture\n",
				cmd.ErrPrefix(),
			)
			os.Exit(1)
		}

		// --library-overwrite-enabled is only meaningful in architecture-scoped mode
		// where multiple libraries are loaded into an AlzLib instance.
		if libraryOverwriteEnabled && len(libraryRefs) == 0 {
			cmd.PrintErrf(
				"%s --library-overwrite-enabled requires --library and --architecture\n",
				cmd.ErrPrefix(),
			)
			os.Exit(1)
		}

		// Read the seed cache BEFORE opening the output file, because --from-cache
		// and --output may point to the same path.
		var seedCache *cache.Cache

		if fromCacheFile != "" {
			f, err := os.Open(fromCacheFile)
			if err != nil {
				cmd.PrintErrf(
					"%s could not open seed cache file %s: %v\n",
					cmd.ErrPrefix(), fromCacheFile, err,
				)
				os.Exit(1)
			}

			seedCache, err = cache.NewCache(f)
			f.Close() //nolint:errcheck // close immediately; do not defer so the same path can be opened for writing below

			if err != nil {
				cmd.PrintErrf(
					"%s could not read seed cache %s: %v\n",
					cmd.ErrPrefix(), fromCacheFile, err,
				)
				os.Exit(1)
			}
		}

		var logger *slog.Logger
		if verbose {
			logger = slog.New(slog.NewTextHandler(cmd.OutOrStdout(), &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))
		} else {
			logger = slog.New(slog.DiscardHandler)
		}

		var resultCache *cache.Cache

		if len(libraryRefs) > 0 {
			// Architecture-scoped mode: process the library + architecture and export
			// only the built-in definitions that were actually referenced.
			refs := make(alzlib.LibraryReferences, 0, len(libraryRefs))
			for _, r := range libraryRefs {
				refs = append(refs, parseLibraryReference(r))
			}

			allLibs, err := refs.FetchWithDependencies(cmd.Context())
			if err != nil {
				cmd.PrintErrf(
					"%s could not fetch libraries with dependencies: %v\n",
					cmd.ErrPrefix(), err,
				)
				os.Exit(1)
			}

			az := alzlib.NewAlzLib(nil)
			az.Options.AllowOverwrite = libraryOverwriteEnabled

			if seedCache != nil {
				az.AddCache(seedCache)
			}

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
				cmd.PrintErrf(
					"%s could not create Azure policy client factory: %v\n",
					cmd.ErrPrefix(), err,
				)
				os.Exit(1)
			}

			az.AddPolicyClient(cf)

			if err := az.Init(cmd.Context(), allLibs...); err != nil {
				cmd.PrintErrf("%s could not initialize alzlib: %v\n", cmd.ErrPrefix(), err)
				os.Exit(1)
			}

			h := deployment.NewHierarchy(az)
			if err := h.FromArchitecture(cmd.Context(), architectureName, defaultRootMgID, defaultLocation); err != nil {
				cmd.PrintErrf(
					"%s could not process architecture %q: %v\n",
					cmd.ErrPrefix(), architectureName, err,
				)
				os.Exit(1)
			}

			resultCache = az.ExportBuiltInCache()
		} else {
			// Full-scan mode: fetch all Azure built-in definitions from the tenant.
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
				cmd.PrintErrf(
					"%s could not create Azure policy client factory: %v\n",
					cmd.ErrPrefix(), err,
				)
				os.Exit(1)
			}

			cmd.Printf("Scanning Azure tenant for built-in definitions...\n")

			resultCache, err = cache.NewCacheFromAzure(cmd.Context(), cf, logger)
			if err != nil {
				cmd.PrintErrf("%s could not create cache from Azure: %v\n", cmd.ErrPrefix(), err)
				os.Exit(1)
			}
		}

		f, err := os.Create(outFile)
		if err != nil {
			cmd.PrintErrf(
				"%s could not create output file %s: %v\n",
				cmd.ErrPrefix(), outFile, err,
			)
			os.Exit(1)
		}
		defer f.Close() //nolint:errcheck

		if err := resultCache.Save(f); err != nil {
			cmd.PrintErrf("%s could not write cache file: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		cmd.Printf("Cache written to %s\n", outFile)
		cmd.Printf("  Policy definitions:     %d names, %d total versions\n",
			resultCache.PolicyDefinitionNames(), resultCache.PolicyDefinitionCount())
		cmd.Printf("  Policy set definitions:  %d names, %d total versions\n",
			resultCache.PolicySetDefinitionNames(), resultCache.PolicySetDefinitionCount())
	},
}

func init() {
	createCmd.Flags().
		StringP("output", "o", "alzlib-cache.json.gz", "Path to the output cache file.")
	createCmd.Flags().
		BoolP("verbose", "v", false, "Display detailed progress during cache creation.")
	createCmd.Flags().
		StringArrayP(
			"library", "L", nil,
			"Path or reference to a library. May be specified multiple times. Each value is "+
				"either a local filesystem path (e.g. ./mylib) or an ALZ Library reference of "+
				"the form <member>@<ref> (e.g. platform/alz@2026.01.3). When set together with "+
				"--architecture, creates a minimal cache containing only the definitions "+
				"referenced by the specified architecture.")
	createCmd.Flags().
		StringP(
			"architecture", "a", "",
			"Name of the architecture within the library to process. Requires --library.")
	createCmd.Flags().
		String(
			"from-cache", "",
			"Path to an existing cache file to use as a seed (requires --library and --architecture). "+
				"Definitions found in the seed cache are not re-fetched from Azure, reducing API calls. "+
				"The same path may be used for both --from-cache and --output to update a cache in-place.")
	createCmd.Flags().
		Bool(
			"library-overwrite-enabled", false,
			"Allow later libraries to overwrite definitions, policy assignments, role definitions, "+
				"archetypes and architectures already provided by earlier libraries. Useful when "+
				"layering a custom library on top of a base ALZ library. Requires --library and "+
				"--architecture.")
}

// parseLibraryReference converts a CLI library argument into a LibraryReference.
// Values containing an "@" separator and not starting with a filesystem path
// indicator (".", "/", "\" or a Windows drive letter such as "C:") are treated
// as ALZ Library references of the form <member>@<ref>. Everything else is
// treated as a local custom library path.
func parseLibraryReference(s string) alzlib.LibraryReference {
	if idx := strings.LastIndex(s, "@"); idx > 0 {
		path := s[:idx]
		ref := s[idx+1:]
		if ref != "" && !looksLikeLocalPath(path) {
			return alzlib.NewAlzLibraryReference(path, ref)
		}
	}

	return alzlib.NewCustomLibraryReference(s)
}

// looksLikeLocalPath reports whether p has a prefix that indicates a local
// filesystem path rather than an ALZ Library member path.
func looksLikeLocalPath(p string) bool {
	if strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return true
	}
	// Windows drive letter, e.g. "C:" or "c:".
	if len(p) >= 2 && p[1] == ':' {
		c := p[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}

	return false
}
