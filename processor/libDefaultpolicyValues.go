// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

// LibDefaultPolicyValue represents the default policy values that allow a single value to be mapped into different assignments.
type LibDefaultPolicyValue struct {
	Name              string                             `json:"name" yaml:"name"`
	PolicyAssignments []LibDefaultPolicyValueAssignments `json:"policy" yaml:"defaults"`
}

type LibDefaultPolicyValueAssignments struct {
	PolicyAssignmentName string   `json:"policy_assignment_name" yaml:"policy_assignment_name"`
	ParameterNames       []string `json:"parameter_names" yaml:"parameter_names"`
}
