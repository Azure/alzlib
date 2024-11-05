// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
)

func TestDefaultPolicyAssignmentValues_AssignmentParameterComboExists(t *testing.T) {
	d := DefaultPolicyAssignmentValues{
		"Default1": DefaultPolicyAssignmentValuesValue{
			assignment2Parameters: map[string]mapset.Set[string]{
				"Assignment1": mapset.NewSet("Parameter1", "Parameter2"),
				"Assignment2": mapset.NewSet("Parameter3", "Parameter4"),
			},
			description: "",
		},
		"Default2": DefaultPolicyAssignmentValuesValue{
			assignment2Parameters: map[string]mapset.Set[string]{
				"Assignment3": mapset.NewSet("Parameter5", "Parameter6"),
				"Assignment4": mapset.NewSet("Parameter7", "Parameter8"),
			},
			description: "",
		},
	}

	tests := []struct {
		assignmentName string
		parameterName  string
		want           bool
	}{
		{"Assignment1", "Parameter1", true},
		{"Assignment2", "Parameter3", true},
		{"Assignment3", "Parameter5", true},
		{"Assignment4", "Parameter8", true},
		{"NonExistentAssignment", "Parameter1", false},
		{"Assignment1", "NonExistentParameter", false},
	}

	for _, tt := range tests {
		t.Run(tt.assignmentName+"_"+tt.parameterName, func(t *testing.T) {
			got := d.AssignmentParameterComboExists(tt.assignmentName, tt.parameterName)
			if got != tt.want {
				t.Errorf("AssignmentParameterComboExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultPolicyAssignmentValues_Add(t *testing.T) {
	d := DefaultPolicyAssignmentValues{}

	// Test adding a new default name and assignment name
	d.Add("Default1", "Assignment1", "", "Parameter1", "Parameter2")
	if !d.AssignmentParameterComboExists("Assignment1", "Parameter1") {
		t.Error("Failed to add assignment and parameter to DefaultPolicyAssignmentValues")
	}

	// Test adding a new assignment name under an existing default name
	d.Add("Default1", "Assignment2", "", "Parameter3", "Parameter4")
	if !d.AssignmentParameterComboExists("Assignment2", "Parameter3") {
		t.Error("Failed to add assignment and parameter to DefaultPolicyAssignmentValues")
	}

	// Test adding a new default name with multiple assignments and parameters
	d.Add("Default2", "Assignment3", "", "Parameter5", "Parameter6")
	d.Add("Default2", "Assignment4", "", "Parameter7", "Parameter8")
	if !d.AssignmentParameterComboExists("Assignment3", "Parameter5") || !d.AssignmentParameterComboExists("Assignment4", "Parameter8") {
		t.Error("Failed to add assignments and parameters to DefaultPolicyAssignmentValues")
	}
}
