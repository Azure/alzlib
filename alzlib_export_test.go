package alzlib_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/to"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

func TestNewAlzLibOptions(t *testing.T) {
	az := alzlib.NewAlzLib()
	assert.Equal(t, 10, az.Options.Parallelism)
}

func TestNewAlzLibOptionsError(t *testing.T) {
	az := new(alzlib.AlzLib)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	assert.ErrorContains(t, az.Init(ctx), "parallelism")
	az.Options = new(alzlib.AlzLibOptions)
	assert.ErrorContains(t, az.Init(ctx), "parallelism")
}

// ExampleAlzLib_E2E demonstrates the creation of a new AlzLib based a sample directory.
func ExampleAlzLib_Init() {
	az := alzlib.NewAlzLib()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirfs := os.DirFS("./testdata/simple")
	if err := az.Init(ctx, dirfs); err != nil {
		fmt.Println(err)
		return
	}

	wkpv := &alzlib.WellKnownPolicyValues{
		DefaultLocation:                to.Ptr("eastus"),
		DefaultLogAnalyticsWorkspaceId: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/test"),
		PrivateDnsZoneResourceGroupId:  to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test"),
	}
	arch, err := az.CopyArchetype("root", wkpv)
	if err != nil {
		fmt.Println(err)
		return
	}
	req := alzlib.AlzManagementGroupAddRequest{
		Id:               "test",
		DisplayName:      "test",
		ParentId:         "00000000-0000-0000-0000-000000000000",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	if err := az.AddManagementGroupToDeployment(ctx, req); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Management groups: %v", az.Deployment.ListManagementGroups())

	// Output:
	// Management groups: [test]
}
