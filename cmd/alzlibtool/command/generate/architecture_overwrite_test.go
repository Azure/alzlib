// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package generate

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helperEnvVar, when set, makes the test binary run the generate architecture command instead
// of the tests. This lets the tests observe the os.Exit calls made by the command as an exit code.
const helperEnvVar = "ALZLIBTOOL_GENERATE_ARCHITECTURE_HELPER_ARGS"

// helperArgSeparator separates the command arguments passed via helperEnvVar.
// Environment variables cannot contain NUL, and no argument contains a newline.
const helperArgSeparator = "\n"

// Fixtures shared with the check and document command tests. Architecture "shared" is provided
// by the dependency and redefined by the member.
const (
	overwriteMemberLib   = "../testdata/libraryoverwrite/member"
	overwritePdMemberLib = "../testdata/libraryoverwrite/pdmember"
	sharedArchitecture   = "shared"
)

func TestMain(m *testing.M) {
	if rawArgs, ok := os.LookupEnv(helperEnvVar); ok {
		// generateArchitectureBaseCmd has GenerateBaseCmd as its parent, so the tree must run.
		cmd := GenerateBaseCmd
		cmd.SetArgs(append([]string{"architecture"}, strings.Split(rawArgs, helperArgSeparator)...))

		if err := cmd.ExecuteContext(context.Background()); err != nil {
			os.Exit(1)
		}

		os.Exit(0)
	}

	os.Exit(m.Run())
}

// runGenerateArchitecture runs the command in a child process and returns stdout, stderr and
// the exit code separately, so the JSON artifact can be checked independently of warnings.
func runGenerateArchitecture(t *testing.T, args ...string) (string, string, int) {
	t.Helper()

	cmd := exec.Command(os.Args[0])

	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("%s=%s", helperEnvVar, strings.Join(args, helperArgSeparator)),
	)

	var stdout, stderr strings.Builder

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}

	var exitErr *exec.ExitError

	require.ErrorAs(t, err, &exitErr, "unexpected error running generate architecture: %v", err)

	return stdout.String(), stderr.String(), exitErr.ExitCode()
}

func Test_generateArchitectureCmd_overwriteFlagDefault(t *testing.T) {
	f := generateArchitectureBaseCmd.Flags().Lookup("library-overwrite-enabled")
	require.NotNil(t, f, "library-overwrite-enabled flag should be registered")
	assert.Equal(t, "false", f.DefValue)
}

func Test_generateArchitectureCmd_overwriteDisabledByDefault(t *testing.T) {
	_, stderr, code := runGenerateArchitecture(t, overwriteMemberLib, sharedArchitecture)

	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "could not initialize alzlib")
	assert.Contains(t, stderr, "already exists in the library")
}

// Test_generateArchitectureCmd_overwriteEnabled asserts the warning goes to stderr so that the
// JSON on stdout stays parseable in a pipeline.
func Test_generateArchitectureCmd_overwriteEnabled(t *testing.T) {
	stdout, stderr, code := runGenerateArchitecture(
		t, overwriteMemberLib, sharedArchitecture, "--library-overwrite-enabled",
	)

	require.Equal(t, 0, code, "stderr: %s", stderr)
	assert.Contains(t, stderr, "Warning:")

	var parsed []map[string]any

	require.NoError(t, json.Unmarshal([]byte(stdout), &parsed), "stdout must remain valid JSON")
	assert.NotEmpty(t, parsed)
}

// Test_generateArchitectureCmd_outputAssetContract pins what actually lands in the deployment
// artifact: the member policy assignment wins, but a redefined policy definition still comes
// from the dependency, because the engine keeps the dependency version for policy (set)
// definitions.
func Test_generateArchitectureCmd_outputAssetContract(t *testing.T) {
	memberOut := t.TempDir()

	_, stderr, code := runGenerateArchitecture(
		t, overwriteMemberLib, sharedArchitecture, "--library-overwrite-enabled", "--output", memberOut,
	)
	require.Equal(t, 0, code, "stderr: %s", stderr)
	assert.Contains(t, readGeneratedAsset(t, memberOut, "shared-pa"), "PA from member")

	pdMemberOut := t.TempDir()

	_, stderr, code = runGenerateArchitecture(
		t, overwritePdMemberLib, sharedArchitecture, "--library-overwrite-enabled", "--output", pdMemberOut,
	)
	require.Equal(t, 0, code, "stderr: %s", stderr)

	definition := readGeneratedAsset(t, pdMemberOut, "dependency-pd")

	assert.Contains(t, definition, "PD from dependency",
		"policy definitions keep the dependency version, see the flag help")
	assert.NotContains(t, definition, "PD from pdmember")
}

func readGeneratedAsset(t *testing.T, dir, name string) string {
	t.Helper()

	var found string

	require.NoError(t, filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasPrefix(d.Name(), name+".") {
			return nil
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		found = string(b)

		return nil
	}))

	require.NotEmpty(t, found, "no generated asset found for %q under %s", name, dir)

	return found
}
