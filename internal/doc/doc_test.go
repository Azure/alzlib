package doc

import (
	"bytes"
	"context"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/stretchr/testify/require"
)

func TestAlzlibReadmeMd(t *testing.T) {
	ctx := context.Background()
	lib := alzlib.NewAlzLibraryReference("platform/alz", "2024.07.02")
	_, err := lib.Fetch(ctx, "0")
	require.NoError(t, err)
	var buf bytes.Buffer
	err = AlzlibReadmeMd(ctx, &buf, lib)
	t.Log(buf.String())
	require.NoError(t, err)
}
