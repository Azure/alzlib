// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

type LibDefaultPolicyValues struct {
	Defaults []LibDefaultPolicyValuesDefaults `json:"defaults" yaml:"defaults"`
}

// LibDefaultPolicyValues represents the default policy values that allow a single value to be mapped into different assignments.
type LibDefaultPolicyValuesDefaults struct {
	DefaultName       string                             `json:"default_name" yaml:"default_name"`
	PolicyAssignments []LibDefaultPolicyValueAssignments `json:"policy_assignments" yaml:"policy_assignments"`
}

type LibDefaultPolicyValueAssignments struct {
	PolicyAssignmentName string   `json:"policy_assignment_name" yaml:"policy_assignment_name"`
	ParameterNames       []string `json:"parameter_names" yaml:"parameter_names"`
}
