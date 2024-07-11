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
	fs, err := alzlib.FetchAzureLandingZonesLibraryMember(ctx, "platform/alz", "2024.07.02", "0")
	require.NoError(t, err)
	var buf bytes.Buffer
	err = AlzlibReadmeMd(ctx, &buf, fs)
	t.Log(buf.String())
	require.NoError(t, err)
}
