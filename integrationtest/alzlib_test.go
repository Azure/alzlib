// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package integrationtest

import (
	"context"
	"os"
	"testing"

	"github.com/Azure/alzlib"
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

// ExampleAlzLib_Init demonstrates the creation of a new AlzLib based a sample directory.
func ExampleAlzLib_Init() {
	// TODO: refactor this when deployment package takes architecture as input
	os.Exit(0)
	// az := alzlib.NewAlzLib(nil)
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	// dirfs := os.DirFS("../testdata/simple")
	// if err := az.Init(ctx, dirfs); err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// arch, err := az.CopyArchetype("root")
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// depl := deployment.NewHierarchy(az)
	// req := deployment.ManagementGroupAddRequest{
	// 	Id:               "test",
	// 	DisplayName:      "test",
	// 	ParentId:         "00000000-0000-0000-0000-000000000000",
	// 	ParentIsExternal: true,
	// 	Archetype:        arch,
	// }
	// if _, err := depl.AddManagementGroup(ctx, req); err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Printf("Management groups: %v", depl.ListManagementGroups())

	// Output:
	// Management groups: [test]
}
