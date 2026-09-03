// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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

// TestAlzlibReadmeMdWithOptionsNilMatchesDefault pins that the original entry point keeps its
// exact behaviour now that it delegates to the options-aware one.
func TestAlzlibReadmeMdWithOptionsNilMatchesDefault(t *testing.T) {
	ctx := context.Background()
	lib := alzlib.NewCustomLibraryReference("../../testdata/simple")
	_, err := lib.Fetch(ctx, "simple")
	require.NoError(t, err)

	var withDefaults, withNilOptions bytes.Buffer

	require.NoError(t, AlzlibReadmeMd(ctx, &withDefaults, lib))
	require.NoError(t, AlzlibReadmeMdWithOptions(ctx, &withNilOptions, nil, lib))

	require.Equal(t, withDefaults.String(), withNilOptions.String())
}
