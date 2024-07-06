package alzlib_test

import (
	"context"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/stretchr/testify/require"
)

func TestInitWithLocalOverrideOfAlzLibrary(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	ctx := context.Background()
	lib1, err := alzlib.FetchAzureLandingZonesLibraryMember(ctx, "platform/alz", "2024.07.01", "0")
	require.NoError(t, err)
	lib2, err := alzlib.FetchLibraryByGetterString(ctx, "./testdata/overrideAlzLibrary", "1")
	require.NoError(t, err)
	err = az.Init(ctx, lib1, lib2)
	require.NoError(t, err)
}
