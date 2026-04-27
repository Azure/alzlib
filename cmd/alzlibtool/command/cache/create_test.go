// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cache

import (
	"testing"

	"github.com/Azure/alzlib"
	"github.com/stretchr/testify/assert"
)

func TestParseLibraryReference(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     string
		wantAlz   bool
		wantPath  string
		wantRef   string // only for ALZ refs
		wantCustS string // only for custom refs (String())
	}{
		{
			name:     "alz reference",
			input:    "platform/alz@2026.01.3",
			wantAlz:  true,
			wantPath: "platform/alz",
			wantRef:  "2026.01.3",
		},
		{
			name:     "alz reference single segment",
			input:    "alz@2024.07.01",
			wantAlz:  true,
			wantPath: "alz",
			wantRef:  "2024.07.01",
		},
		{
			name:      "local relative path",
			input:     "./mylib",
			wantAlz:   false,
			wantCustS: "./mylib",
		},
		{
			name:      "local relative path with at sign",
			input:     "./mylib@dev",
			wantAlz:   false,
			wantCustS: "./mylib@dev",
		},
		{
			name:      "absolute path",
			input:     "/tmp/lib",
			wantAlz:   false,
			wantCustS: "/tmp/lib",
		},
		{
			name:      "windows-style path",
			input:     `\\share\lib`,
			wantAlz:   false,
			wantCustS: `\\share\lib`,
		},
		{
			name:      "no separator",
			input:     "platform/alz",
			wantAlz:   false,
			wantCustS: "platform/alz",
		},
		{
			name:      "trailing at sign with empty ref",
			input:     "platform/alz@",
			wantAlz:   false,
			wantCustS: "platform/alz@",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := parseLibraryReference(tc.input)
			if tc.wantAlz {
				ref, ok := got.(*alzlib.AlzLibraryReference)
				if assert.True(t, ok, "expected AlzLibraryReference, got %T", got) {
					assert.Equal(t, tc.wantPath, ref.Path())
					assert.Equal(t, tc.wantRef, ref.Ref())
				}
			} else {
				_, ok := got.(*alzlib.CustomLibraryReference)
				assert.True(t, ok, "expected CustomLibraryReference, got %T", got)
				assert.Equal(t, tc.wantCustS, got.String())
			}
		})
	}
}
