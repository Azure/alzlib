// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package document

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

// helperEnvVar, when set, makes the test binary run the document library command instead of the
// tests. This lets the tests observe the os.Exit calls made by the command as an exit code.
const helperEnvVar = "ALZLIBTOOL_DOCUMENT_LIBRARY_HELPER_ARGS"

// helperArgSeparator separates the command arguments passed via helperEnvVar.
// Environment variables cannot contain NUL, and no argument contains a newline.
const helperArgSeparator = "\n"

// overwriteMemberLib is shared with the check and generate command tests.
const overwriteMemberLib = "../testdata/libraryoverwrite/member"

func TestMain(m *testing.M) {
	if rawArgs, ok := os.LookupEnv(helperEnvVar); ok {
		// documentLibraryBaseCmd has DocumentBaseCmd as its parent, so the whole tree must run.
		cmd := DocumentBaseCmd
		cmd.SetArgs(append([]string{"library"}, strings.Split(rawArgs, helperArgSeparator)...))

		if err := cmd.ExecuteContext(context.Background()); err != nil {
			os.Exit(1)
		}

		os.Exit(0)
	}

	os.Exit(m.Run())
}

// runDocumentLibrary runs the command in a child process and returns stdout, stderr and the
// exit code separately, so that the Markdown artifact can be checked independently of warnings.
func runDocumentLibrary(t *testing.T, args ...string) (string, string, int) {
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

	require.ErrorAs(t, err, &exitErr, "unexpected error running document library: %v", err)

	return stdout.String(), stderr.String(), exitErr.ExitCode()
}

func Test_documentLibraryCmd_overwriteFlagDefault(t *testing.T) {
	f := documentLibraryBaseCmd.Flags().Lookup("library-overwrite-enabled")
	require.NotNil(t, f, "library-overwrite-enabled flag should be registered")
	assert.Equal(t, "false", f.DefValue)
}

func Test_documentLibraryCmd_overwriteDisabledByDefault(t *testing.T) {
	_, stderr, code := runDocumentLibrary(t, overwriteMemberLib)

	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "already exists in the library")
}

// Test_documentLibraryCmd_overwriteEnabled asserts that the member archetype wins, and that the
// warning goes to stderr so the Markdown on stdout stays usable.
func Test_documentLibraryCmd_overwriteEnabled(t *testing.T) {
	stdout, stderr, code := runDocumentLibrary(t, overwriteMemberLib, "--library-overwrite-enabled")

	require.Equal(t, 0, code, "stderr: %s", stderr)
	assert.Contains(t, stdout, "member-only-pa")
	assert.Contains(t, stderr, "Warning:")
	assert.NotContains(t, stdout, "Warning:")
}
