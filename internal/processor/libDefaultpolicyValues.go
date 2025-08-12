// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package processor

// LibDefaultPolicyValues represents the top level value that allow a single value to be
// mapped into different assignments.
type LibDefaultPolicyValues struct {
	Defaults []LibDefaultPolicyValuesDefaults `json:"defaults" yaml:"defaults"`
}

// LibDefaultPolicyValuesDefaults represents the default policy values that allow a single value to be
// mapped into different assignments.
type LibDefaultPolicyValuesDefaults struct {
	DefaultName       string                             `json:"default_name"          yaml:"default_name"`
	Description       string                             `json:"description,omitempty" yaml:"description"`
	PolicyAssignments []LibDefaultPolicyValueAssignments `json:"policy_assignments"    yaml:"policy_assignments"`
}

// LibDefaultPolicyValueAssignments represents the policy assignments for a default value.
type LibDefaultPolicyValueAssignments struct {
	PolicyAssignmentName string   `json:"policy_assignment_name" yaml:"policy_assignment_name"`
	ParameterNames       []string `json:"parameter_names"        yaml:"parameter_names"`
}
