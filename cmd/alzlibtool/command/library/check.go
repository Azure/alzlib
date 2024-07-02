package library

import (
	"fmt"
	"os"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/tools/checker"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/spf13/cobra"
)

// CheckCmd represents the policydefinition command.
var CheckCmd = cobra.Command{
	Use:   "check [flags] dir",
	Short: "Perform operations on an alzlib library member.",
	Long:  `Primarily used a a tool to check the validity of a library member.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		az := alzlib.NewAlzLib(nil)
		dirFs := os.DirFS(args[0])
		az.Init(cmd.Context(), dirFs)

		chk := checker.NewValidator(checkAllDefinitionsAreReferenced)
		err := chk.Validate(az)
		if err != nil {
			cmd.PrintErrf("%s library check error: %v\n", cmd.ErrPrefix(), err)
			os.Exit(1)
		}
	},
}

func checkAllDefinitionsAreReferenced(azany any) error {
	az, ok := azany.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: expected *alzlib.AlzLib, got %T", azany)
	}
	// Test if we have policy (set) definitions that are not referenced by any archetype
	referencedPds := mapset.NewThreadUnsafeSet[string]()
	referencedPsds := mapset.NewThreadUnsafeSet[string]()
	referencedRds := mapset.NewThreadUnsafeSet[string]()
	for _, archetypeName := range az.Archetypes() {
		archetype, _ := az.Archetype(archetypeName) // nolint: errcheck
		referencedPds = referencedPds.Union(archetype.PolicyDefinitions)
		referencedPsds = referencedPsds.Union(archetype.PolicySetDefinitions)
		referencedRds = referencedRds.Union(archetype.RoleDefinitions)
	}
	unreferencedPds := mapset.NewThreadUnsafeSet(az.PolicyDefinitions()...).Difference(referencedPds).ToSlice()
	unreferencedPsds := mapset.NewThreadUnsafeSet(az.PolicySetDefinitions()...).Difference(referencedPsds).ToSlice()
	unreferencedRds := mapset.NewThreadUnsafeSet(az.RoleDefinitions()...).Difference(referencedRds).ToSlice()
	if len(unreferencedPds) > 0 || len(unreferencedPsds) > 0 || len(unreferencedRds) > 0 {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: found unreferenced definitions [policyDefinitions] [policySetDefinitions] [roleDefinitions]: %v, %v, %v", unreferencedPds, unreferencedPsds, unreferencedRds)
	}
	return nil
}
