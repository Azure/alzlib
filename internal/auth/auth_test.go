// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package auth

import (
	"os"
	"testing"
)

func TestGetFirstSetEnvVar_NoVarsSet_ReturnsEmpty(t *testing.T) {
	// Ensure none of the vars are set
	_ = os.Unsetenv("TEST_AUTH_VAR_1")
	_ = os.Unsetenv("TEST_AUTH_VAR_2")

	if got := getFirstSetEnvVar("TEST_AUTH_VAR_1", "TEST_AUTH_VAR_2"); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestGetFirstSetEnvVar_FirstSetReturnsValue(t *testing.T) {
	t.Setenv("TEST_AUTH_VAR_1", "first")
	t.Setenv("TEST_AUTH_VAR_2", "second")

	if got := getFirstSetEnvVar("TEST_AUTH_VAR_1", "TEST_AUTH_VAR_2"); got != "first" {
		t.Fatalf("expected 'first', got %q", got)
	}
}

func TestGetFirstSetEnvVar_SecondUsedWhenFirstEmpty(t *testing.T) {
	_ = os.Unsetenv("TEST_AUTH_VAR_1")
	t.Setenv("TEST_AUTH_VAR_2", "second")

	if got := getFirstSetEnvVar("TEST_AUTH_VAR_1", "TEST_AUTH_VAR_2"); got != "second" {
		t.Fatalf("expected 'second', got %q", got)
	}
}

func TestGetFirstSetEnvVar_NoArgs_ReturnsEmpty(t *testing.T) {
	if got := getFirstSetEnvVar(); got != "" {
		t.Fatalf("expected empty string for no args, got %q", got)
	}
}

func TestUpdateBoolValueAnyTrue_CurrentTrueKept(t *testing.T) {
	_ = os.Unsetenv("TEST_BOOL_VAR")

	if got := updateBoolValueAnyTrue(true, "TEST_BOOL_VAR"); got != true {
		t.Fatalf("expected true to be kept, got %v", got)
	}
}

func TestUpdateBoolValueAnyTrue_EnvVarTrue(t *testing.T) {
	t.Setenv("TEST_BOOL_VAR", "true")

	if got := updateBoolValueAnyTrue(false, "TEST_BOOL_VAR"); got != true {
		t.Fatalf("expected true when env var is 'true', got %v", got)
	}
}

func TestUpdateBoolValueAnyTrue_EnvVarOne(t *testing.T) {
	t.Setenv("TEST_BOOL_VAR", "1")

	if got := updateBoolValueAnyTrue(false, "TEST_BOOL_VAR"); got != true {
		t.Fatalf("expected true when env var is '1', got %v", got)
	}
}

func TestUpdateBoolValueAnyTrue_InvalidBoolIgnored(t *testing.T) {
	t.Setenv("TEST_BOOL_VAR", "notabool")

	if got := updateBoolValueAnyTrue(false, "TEST_BOOL_VAR"); got != false {
		t.Fatalf("expected false when env var is invalid, got %v", got)
	}
}

func TestUpdateBoolValueAnyTrue_MultipleVars(t *testing.T) {
	t.Setenv("TEST_BOOL_VAR_2", "true")

	if got := updateBoolValueAnyTrue(false, "TEST_BOOL_VAR_1", "TEST_BOOL_VAR_2"); got != true {
		t.Fatalf("expected true when later var is true, got %v", got)
	}
}
