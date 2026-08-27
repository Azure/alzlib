// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package check

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helperEnvVar, when set, makes the test binary run the library check command instead of the
// tests. This lets the tests observe the os.Exit calls made by the command as an exit code.
const helperEnvVar = "ALZLIBTOOL_CHECK_LIBRARY_HELPER_ARGS"

// helperArgSeparator separates the command arguments passed via helperEnvVar.
// Environment variables cannot contain NUL, and no argument contains a newline.
const helperArgSeparator = "\n"

// Fixtures shared with the generate and document command tests.
const (
	overwriteMemberLib   = "../testdata/libraryoverwrite/member"
	overwritePdMemberLib = "../testdata/libraryoverwrite/pdmember"
	standaloneLib        = "../testdata/standalone"
)

func TestMain(m *testing.M) {
	if rawArgs, ok := os.LookupEnv(helperEnvVar); ok {
		// libraryCmd has CheckCmd as its parent, so the whole tree must be executed.
		cmd := CheckCmd
		cmd.SetArgs(append([]string{"library"}, strings.Split(rawArgs, helperArgSeparator)...))

		if err := cmd.ExecuteContext(context.Background()); err != nil {
			os.Exit(1)
		}

		os.Exit(0)
	}

	os.Exit(m.Run())
}

// runCheckLibrary runs the library check command in a child process and returns its combined
// output and exit code.
func runCheckLibrary(t *testing.T, args ...string) (string, int) {
	t.Helper()

	cmd := exec.Command(os.Args[0])

	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("%s=%s", helperEnvVar, strings.Join(args, helperArgSeparator)),
	)

	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}

	var exitErr *exec.ExitError

	require.ErrorAs(t, err, &exitErr, "unexpected error running check library: %v", err)

	return string(out), exitErr.ExitCode()
}

func Test_libraryCmd_overwriteFlagDefault(t *testing.T) {
	f := libraryCmd.Flags().Lookup("library-overwrite-enabled")
	require.NotNil(t, f, "library-overwrite-enabled flag should be registered")
	assert.Equal(t, "false", f.DefValue)
}

func Test_libraryCmd_help(t *testing.T) {
	out, code := runCheckLibrary(t, "--help")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "--library-overwrite-enabled")
}

func Test_libraryCmd_overwriteDisabledByDefault(t *testing.T) {
	out, code := runCheckLibrary(t, overwriteMemberLib, "--offline")
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "already exists in the library")
}

// Test_libraryCmd_overwriteEnabled asserts that the member version wins: the member defaults
// require memberParameter, which only exists on the definition referenced by the member version
// of shared-pa, so passing the defaults check proves the dependency version was replaced.
func Test_libraryCmd_overwriteEnabled(t *testing.T) {
	out, code := runCheckLibrary(t, overwriteMemberLib, "--offline", "--library-overwrite-enabled")
	assert.Equal(t, 0, code, "output: %s", out)
	assert.NotContains(t, out, "already exists in the library")
}

func Test_libraryCmd_noConflictWithoutFlag(t *testing.T) {
	out, code := runCheckLibrary(t, standaloneLib, "--offline")
	assert.Equal(t, 0, code, "output: %s", out)
}

// Test_libraryCmd_policyDefinitionOverrideNotApplied pins current engine behaviour: for policy
// (set) definitions the flag only suppresses the duplicate error, the dependency version is
// kept. The pdmember version of dependency-pd adds the parameter its defaults require, so the
// defaults check failing proves the member version was discarded.
func Test_libraryCmd_policyDefinitionOverrideNotApplied(t *testing.T) {
	out, code := runCheckLibrary(t, overwritePdMemberLib, "--offline", "--library-overwrite-enabled")
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "not present in the referenced definition")
}
