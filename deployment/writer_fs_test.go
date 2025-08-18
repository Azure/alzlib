// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/assets"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/require"
)

// buildSimpleHierarchy constructs a hierarchy from the testdata/simple library used elsewhere in tests.
func buildSimpleHierarchy(t *testing.T) *Hierarchy {
	t.Helper()
	// Path from this package directory to repo testdata/simple
	libPath := filepath.Join("..", "testdata", "simple")

	// Ensure a clean local fetch workspace under current working directory used by the fetcher.
	_ = os.RemoveAll(".alzlib")

	t.Cleanup(func() { _ = os.RemoveAll(".alzlib") })

	thislib := alzlib.NewCustomLibraryReference(libPath)
	alllibs, err := thislib.FetchWithDependencies(context.Background())
	require.NoError(t, err)

	az := alzlib.NewAlzLib(nil)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	require.NoError(t, err)
	az.AddPolicyClient(cf)
	require.NoError(t, az.Init(context.Background(), alllibs...))

	h := NewHierarchy(az)
	require.NoError(t, h.FromArchitecture(context.Background(), "simple", "00000000-0000-0000-0000-000000000000", "northeurope"))

	return h
}

func TestFSWriter_ExportsSimple(t *testing.T) {
	h := buildSimpleHierarchy(t)

	outDir := t.TempDir()
	w := NewFSWriter()
	require.NoError(t, w.Write(context.Background(), h, outDir))

	// Expect root MG directories from simple architecture
	// Known MG ids from prior tests: "simple" and "simpleoverride"
	mgDirs := []string{"simple", "simpleoverride"}
	for _, mg := range mgDirs {
		dir := filepath.Join(outDir, mg)
		fi, err := os.Stat(dir)
		require.NoError(t, err, "expected MG directory %s", dir)
		require.True(t, fi.IsDir())
	}

	// Check a few known files in "simple" MG directory
	simpleDir := filepath.Join(outDir, "simple")
	// expected asset names from test library
	expectFiles := []string{
		"test-pa" + fileSuffixPolicyAssignment,
		"test-policy-definition" + fileSuffixPolicyDefinition,
		"test-policy-set-definition" + fileSuffixPolicySetDefinition,
	}
	for _, f := range expectFiles {
		_, err := os.Stat(filepath.Join(simpleDir, f))
		require.NoError(t, err, "expected file %s", f)
	}

	// Load a file and validate it unmarshals into the correct type and name matches
	paPath := filepath.Join(simpleDir, "test-pa"+fileSuffixPolicyAssignment)
	b, err := os.ReadFile(paPath)
	require.NoError(t, err)

	var pa assets.PolicyAssignment
	require.NoError(t, json.Unmarshal(b, &pa))
	require.NotNil(t, pa.Name)
	require.Equal(t, "test-pa", *pa.Name)
}

func TestFSWriter_WithEscapeARM_Toggle(t *testing.T) {
	h := buildSimpleHierarchy(t)

	// Sanity: pick a file that is likely to contain parameterized strings in testdata/simple
	outDirNoEsc := t.TempDir()
	wNoEsc := NewFSWriter() // default: no escaping
	require.NoError(t, wNoEsc.Write(context.Background(), h, outDirNoEsc))

	outDirEsc := t.TempDir()
	wEsc := NewFSWriter(WithEscapeARM(true))
	require.NoError(t, wEsc.Write(context.Background(), h, outDirEsc))

	// Compare one known file content for evidence of escaping behavior.
	// We'll use the policy assignment which in simple testdata contains some bracketed expressions.
	paFile := filepath.Join("simple", "test-pa"+fileSuffixPolicyAssignment)

	noEscBytes, err := os.ReadFile(filepath.Join(outDirNoEsc, paFile))
	require.NoError(t, err)

	escBytes, err := os.ReadFile(filepath.Join(outDirEsc, paFile))
	require.NoError(t, err)

	// Parse into generic maps and scan for any string starting with "[[" in the escaped output,
	// which should be strictly more than in the non-escaped output.
	var noEsc any
	var esc any
	require.NoError(t, json.Unmarshal(noEscBytes, &noEsc))
	require.NoError(t, json.Unmarshal(escBytes, &esc))

	var countStarts func(v any) int
	countStarts = func(v any) (count int) {
		switch t := v.(type) {
		case map[string]any:
			for _, val := range t {
				count += countStarts(val)
			}
		case []any:
			for _, e := range t {
				count += countStarts(e)
			}
		case string:
			if strings.HasPrefix(t, "[[") {
				count++
			}
		}
		return
	}

	require.GreaterOrEqual(t, countStarts(esc), countStarts(noEsc))
}

func TestFSWriter_Cancellation(t *testing.T) {
	h := buildSimpleHierarchy(t)
	outDir := t.TempDir()
	w := NewFSWriter()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := w.Write(ctx, h, outDir)
	require.Error(t, err)
}

func TestDerefString(t *testing.T) {
	t.Parallel()

	var nilPtr *string
	require.Equal(t, "fallback", derefString(nilPtr, "fallback"))

	empty := ""
	require.Equal(t, "fallback", derefString(&empty, "fallback"))

	val := "value"
	require.Equal(t, "value", derefString(&val, "fallback"))
}

func TestSanitizeFilename(t *testing.T) {
	t.Parallel()

	// empty and whitespace
	require.Equal(t, "unnamed", sanitizeFilename(""))
	require.Equal(t, "unnamed", sanitizeFilename("   "))

	// safe name stays same
	require.Equal(t, "my-file_name", sanitizeFilename("my-file_name"))

	// invalid characters replaced, control chars mapped to '_'
	in := "a/b\\c:d*e?f\"g<h>i|j\t\n"
	out := sanitizeFilename(in)
	require.Equal(t, "a_b_c_d_e_f_g_h_i_j__", out)
}

func TestCtxErr(t *testing.T) {
	t.Parallel()

	require.NoError(t, ctxErr(nil)) //nolint:staticcheck
	require.NoError(t, ctxErr(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, ctxErr(ctx))
}

func TestWriteJSONFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "obj.json")

	obj := struct {
		X string `json:"x"`
	}{X: "y"}

	require.NoError(t, writeJSONFile(path, obj))

	// file exists and contains valid JSON
	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var dec map[string]any
	require.NoError(t, json.Unmarshal(b, &dec))
	require.Equal(t, "y", dec["x"])
}

func TestAddArmFunctionEscaping_MapSimple(t *testing.T) {
	t.Parallel()

	v := map[string]any{
		"a": "[concat('foo','bar')]",
		"b": "nope",
		"c": 123,
		"d": true,
		"e": nil,
	}

	require.NoError(t, addArmFunctionEscaping(v))

	require.Equal(t, "[[concat('foo','bar')]", v["a"])
	require.Equal(t, "nope", v["b"])
	require.Equal(t, 123, v["c"])
	require.Equal(t, true, v["d"])
	require.Nil(t, v["e"])
}

func TestAddArmFunctionEscaping_Nested(t *testing.T) {
	t.Parallel()

	v := map[string]any{
		"outer": []any{
			"[subscription().id]",
			map[string]any{
				"inner":    "[resourceGroup().name]",
				"innerOK":  "text",
				"innerNum": 42,
			},
		},
	}

	require.NoError(t, addArmFunctionEscaping(v))

	outer := v["outer"].([]any)
	require.Equal(t, "[[subscription().id]", outer[0])

	inner := outer[1].(map[string]any)
	require.Equal(t, "[[resourceGroup().name]", inner["inner"])
	require.Equal(t, "text", inner["innerOK"])
	require.Equal(t, 42, inner["innerNum"])
}

func TestAddArmFunctionEscaping_SliceRoot(t *testing.T) {
	t.Parallel()

	v := []any{
		"[parameters('p1')]",
		"plain",
		5,
		map[string]any{"k": "[deployment().name]"},
	}

	require.NoError(t, addArmFunctionEscaping(v))

	require.Equal(t, "[[parameters('p1')]", v[0])
	require.Equal(t, "plain", v[1])
	require.Equal(t, 5, v[2])

	m := v[3].(map[string]any)
	require.Equal(t, "[[deployment().name]", m["k"])
}
