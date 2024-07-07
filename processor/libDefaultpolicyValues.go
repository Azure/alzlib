// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

// LibDefaultPolicyValues represents the default policy values that allow a single value to be mapped into different assignments.
type LibDefaultPolicyValues struct {
	Defaults []struct {
		DefaultName       string `json:"default_name" yaml:"default_name"`
		PolicyAssignments []struct {
			PolicyAssignmentName string   `json:"policy_assignment_name" yaml:"policy_assignment_name"`
			ParameterNames       []string `json:"parameter_names" yaml:"parameter_names"`
		} `json:"policy_assignments" yaml:"policy_assignments"`
	} `json:"defaults" yaml:"defaults"`
}
