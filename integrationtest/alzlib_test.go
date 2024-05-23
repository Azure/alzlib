package integrationtest

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/deployment"
	"github.com/stretchr/testify/assert"
)

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
	az := alzlib.NewAlzLib(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirfs := os.DirFS("./testdata/simple")
	if err := az.Init(ctx, dirfs); err != nil {
		fmt.Println(err)
		return
	}

	arch, err := az.CopyArchetype("root")
	if err != nil {
		fmt.Println(err)
		return
	}

	depl := deployment.NewHierarchy(az)
	req := deployment.ManagementGroupAddRequest{
		Id:               "test",
		DisplayName:      "test",
		ParentId:         "00000000-0000-0000-0000-000000000000",
		ParentIsExternal: true,
		Archetype:        arch,
	}
	if err := depl.AddManagementGroup(ctx, req); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Management groups: %v", depl)

	// Output:
	// Management groups: [test]
}
