// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFetchLibrariesWithDependencies tests fetching libraries with dependencies and they they are
// fetched in the right
// order.
func TestFetchLibrariesWithDependencies(t *testing.T) {
	ctx := context.Background()

	require.NoError(t, os.RemoveAll(".alzlib"))

	defer os.RemoveAll(".alzlib") // nolint: errcheck

	expcted := []string{
		"testdata/dependent-libs/lib2",
		"testdata/dependent-libs/lib1",
		"testdata/dependent-libs/libB",
		"testdata/dependent-libs/libA",
	}
	lib1 := NewCustomLibraryReference("testdata/dependent-libs/lib1")
	libA := NewCustomLibraryReference("testdata/dependent-libs/libA")
	libs := LibraryReferences{lib1, libA}
	libs, err := libs.FetchWithDependencies(ctx)
	require.NoError(t, err)
	require.Len(t, libs, 4)

	result := make([]string, 4)
	for i, lib := range libs {
		result[i] = lib.String()
	}

	assert.ElementsMatch(t, expcted, result)
}

// TestFetchLibrariesWithCommonDependency checks that a libraries having a common dependency is
// fetched only once.
func TestFetchLibrariesWithCommonDependency(t *testing.T) {
	ctx := context.Background()

	require.NoError(t, os.RemoveAll(".alzlib"))

	defer os.RemoveAll(".alzlib") // nolint: errcheck

	expcted := []string{
		"testdata/dependent-libs/lib2",
		"testdata/dependent-libs/lib1",
		"testdata/dependent-libs/lib3",
	}
	lib1 := NewCustomLibraryReference("testdata/dependent-libs/lib1")
	libA := NewCustomLibraryReference("testdata/dependent-libs/lib3")
	libs := LibraryReferences{lib1, libA}
	libs, err := libs.FetchWithDependencies(ctx)
	require.NoError(t, err)
	require.Len(t, libs, 3)

	result := make([]string, 3)
	for i, lib := range libs {
		result[i] = lib.String()
	}

	assert.ElementsMatch(t, expcted, result)
}

// TestNewAlzLibraryReferenceFromFS verifies that Fetch returns the pre-supplied fs.FS
// without performing a download.
func TestNewAlzLibraryReferenceFromFS(t *testing.T) {
	memfs := fstest.MapFS{
		"somefile.txt": &fstest.MapFile{Data: []byte("content")},
	}
	ref := NewAlzLibraryReferenceFromFS("somepath", "someref", memfs)
	got, err := ref.Fetch(context.Background(), t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, fs.FS(memfs), got)
}

// TestNewCustomLibraryReferenceFromFS verifies that Fetch returns the pre-supplied fs.FS
// without invoking go-getter or touching any filesystem cache directory.
func TestNewCustomLibraryReferenceFromFS(t *testing.T) {
	memfs := fstest.MapFS{
		"somefile.txt": &fstest.MapFile{Data: []byte("content")},
	}
	ref := NewCustomLibraryReferenceFromFS("someurl", memfs)
	got, err := ref.Fetch(context.Background(), t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, fs.FS(memfs), got)
}

// TestNewAlzLibraryReferenceFromString verifies parsing of "<path>@<ref>" strings.
func TestNewAlzLibraryReferenceFromString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    string
		wantErr  bool
		wantPath string
		wantRef  string
	}{
		{name: "valid", input: "platform/alz@2026.01.3", wantPath: "platform/alz", wantRef: "2026.01.3"},
		{name: "single segment path", input: "alz@2024.07.01", wantPath: "alz", wantRef: "2024.07.01"},
		{name: "no separator", input: "platform/alz", wantErr: true},
		{name: "empty ref", input: "platform/alz@", wantErr: true},
		{name: "empty path", input: "@2026.01.3", wantErr: true},
		{name: "empty string", input: "", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ref, err := NewAlzLibraryReferenceFromString(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, ref)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, ref)
			assert.Equal(t, tc.wantPath, ref.Path())
			assert.Equal(t, tc.wantRef, ref.Ref())
			// Round-trip via String().
			assert.Equal(t, tc.input, ref.String())
		})
	}
}

// TestNewLibraryReference verifies the universal constructor's detection of
// ALZ Library references vs. custom (URL or local path) references.
func TestNewLibraryReference(t *testing.T) {
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
			name:      "windows drive path with at sign",
			input:     `C:\libs\mylib@dev`,
			wantAlz:   false,
			wantCustS: `C:\libs\mylib@dev`,
		},
		{
			name:      "windows drive path lowercase with at sign",
			input:     `d:/libs/mylib@dev`,
			wantAlz:   false,
			wantCustS: `d:/libs/mylib@dev`,
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

			got := NewLibraryReference(tc.input)
			if tc.wantAlz {
				ref, ok := got.(*AlzLibraryReference)
				if assert.True(t, ok, "expected *AlzLibraryReference, got %T", got) {
					assert.Equal(t, tc.wantPath, ref.Path())
					assert.Equal(t, tc.wantRef, ref.Ref())
				}

				return
			}

			_, ok := got.(*CustomLibraryReference)
			assert.True(t, ok, "expected *CustomLibraryReference, got %T", got)
			assert.Equal(t, tc.wantCustS, got.String())
		})
	}
}
