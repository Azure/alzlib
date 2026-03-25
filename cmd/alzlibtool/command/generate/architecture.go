// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package generate

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/Azure/alzlib"
	alzlibcache "github.com/Azure/alzlib/cache"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/alzlib/internal/auth"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

const (
	// RequiredArchitectureArgs is the number of required arguments for architecture generation.
	RequiredArchitectureArgs = 2
)

var generateArchitectureBaseCmd = cobra.Command{
	Use:   "architecture librarypath name",
	Short: "Generates deployment JSON for the supplied architecture.",
	Long: `Generates deployment JSON for the supplied architecture. ` +
		`This enables deployment with a tool of your choosing.`,
	Args: cobra.ExactArgs(RequiredArchitectureArgs),
	Run: func(cmd *cobra.Command, args []string) {
		thisLib := alzlib.NewCustomLibraryReference(args[0])

		allLibs, err := thisLib.FetchWithDependencies(cmd.Context())
		if err != nil {
			cmd.PrintErrf(
				"%s could not fetch all libraries with dependencies: %v\n",
				cmd.ErrPrefix(),
				err,
			)
			os.Exit(1)
		}

		az := alzlib.NewAlzLib(nil)

		// Load seed cache if --from-cache is specified.
		fromCacheFile, _ := cmd.Flags().GetString("from-cache")
		if fromCacheFile != "" {
			f, err := os.Open(fromCacheFile)
			if err != nil {
				cmd.PrintErrf("%s could not open cache file %s: %v\n", cmd.ErrPrefix(), fromCacheFile, err)
				os.Exit(1)
			}
			defer f.Close() //nolint:errcheck

			c, err := alzlibcache.NewCache(f)
			if err != nil {
				cmd.PrintErrf("%s could not load cache file %s: %v\n", cmd.ErrPrefix(), fromCacheFile, err)
				os.Exit(1)
			}

			az.AddCache(c)
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
			cmd.PrintErrf("%s could not add client to alzlib: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		az.AddPolicyClient(cf)

		if err := az.Init(cmd.Context(), allLibs...); err != nil {
			cmd.PrintErrf("%s could not initialize alzlib: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		h := deployment.NewHierarchy(az)
		rootMg, _ := cmd.Flags().GetString("rootmg")

		location, _ := cmd.Flags().GetString("location")
		if err := h.FromArchitecture(cmd.Context(), args[1], rootMg, location); err != nil {
			cmd.PrintErrf("%s could not generate architecture: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
		// If an output directory is provided, export a filesystem representation and return.
		outDir, _ := cmd.Flags().GetString("output")
		if outDir != "" {
			opts := deployment.FSWriterOptions{}
			if b, _ := cmd.Flags().GetBool("for-alz-bicep"); b {
				opts = deployment.FSWriterOptions{
					ArmEscapePolicyDefinitions:    1,
					ArmEscapePolicySetDefinitions: 2, //nolint:mnd
					ArmEscapeRoleDefinitions:      1,
					ArmEscapePolicyAssignments:    1,
					PolicySetOptions: deployment.FSWriterPolicySetOptions{
						CustomPolicyDefinitionReferencesUpdate: true,
						CustomPolicyDefinitionReferenceRegExp: regexp.MustCompile(
							fmt.Sprintf(`(?i)^/providers/Microsoft\.Management/managementGroups/%s`, args[1]),
						),
						CustomPolicyDefinitionReferenceReplaceValue: "{customPolicyDefinitionScopeId}",
					},
				}
			}

			w := deployment.NewFSWriter(opts)
			if err := w.Write(cmd.Context(), h, outDir); err != nil {
				cmd.PrintErrf("%s could not write filesystem output: %v\n", cmd.ErrPrefix(), err)
				os.Exit(1)
			}

			cmd.Printf("filesystem export written to %s\n", outDir)

			return
		}

		output := make([]*deployment.HierarchyManagementGroup, len(h.ManagementGroupNames()))
		for i, mgName := range h.ManagementGroupNames() {
			output[i] = h.ManagementGroup(mgName)
		}

		outputBytes, err := json.Marshal(output)
		if err != nil {
			cmd.PrintErrf("%s could not marshal output: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}

		cmd.SetOut(os.Stdout)
		cmd.Println(string(outputBytes))
	},
}

func init() {
	generateArchitectureBaseCmd.Flags().
		StringP("rootmg", "r", "00000000-0000-0000-0000-000000000000",
			"The root management group id to use for the deployment.")
	generateArchitectureBaseCmd.Flags().
		StringP("location", "l", "northeurope", "The location to use for the deployment.")
	generateArchitectureBaseCmd.Flags().
		StringP(
			"output",
			"o",
			"",
			"Directory to export the filesystem representation of the hierarchy (per-asset JSON files). "+
				"If set, JSON is not printed to stdout.")

	generateArchitectureBaseCmd.Flags().
		Bool(
			"for-alz-bicep",
			false,
			"When exporting to a directory, add custom ARM escaping and other transformations specific to ALZ Bicep.")

	generateArchitectureBaseCmd.Flags().
		String(
			"from-cache",
			"",
			"Path to a cache file to seed built-in definitions from. "+
				"Definitions found in the cache are used before falling back to Azure API calls, "+
				"reducing the number of requests made to Azure.")
}
