package generate

import (
	"encoding/json"
	"os"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/spf13/cobra"
)

var generateArchitectureBaseCmd = cobra.Command{
	Use:   "architecture librarypath name",
	Short: "Generates deployment JSON for the supplied architecture.",
	Long:  `Generates deployment JSON for the supplied architecture. This enables deployment with a tool of your choosing.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		thislib := alzlib.NewCustomLibraryReference(args[0])
		alllibs, err := thislib.FetchWithDependencies(cmd.Context())
		if err != nil {
			cmd.PrintErrf("%s could not fetch all libraries with dependencies: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
		az := alzlib.NewAlzLib(nil)
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			cmd.PrintErrf("%s could not get Azure credential: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
		cf, err := armpolicy.NewClientFactory("", cred, nil)
		if err != nil {
			cmd.PrintErrf("%s could not add client to alzlib: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
		az.AddPolicyClient(cf)
		if err := az.Init(cmd.Context(), alllibs...); err != nil {
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
	generateArchitectureBaseCmd.Flags().StringP("rootmg", "r", "00000000-0000-0000-0000-000000000000", "The root management group id to use for the deployment.")
	generateArchitectureBaseCmd.Flags().StringP("location", "l", "northeurope", "The location to use for the deployment.")
}
