// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package alzlib

import (
	"maps"
	"slices"

	mapset "github.com/deckarep/golang-set/v2"
)

// DefaultPolicyAssignmentValues is a map of default names to DefaultPolicyAssignmentValuesValue.
// It is used to map a single value to multiple policy assignments.
type DefaultPolicyAssignmentValues map[string]DefaultPolicyAssignmentValuesValue

// DefaultPolicyAssignmentValuesValue is a map of assignments names to parameter names.
type DefaultPolicyAssignmentValuesValue struct {
	assignment2Parameters map[string]mapset.Set[string]
	description           string
}

// NewDefaultPolicyAssignmentValuesValue creates a new DefaultPolicyAssignmentValues instance.
func NewDefaultPolicyAssignmentValuesValue(description string) DefaultPolicyAssignmentValuesValue {
	return DefaultPolicyAssignmentValuesValue{
		assignment2Parameters: make(map[string]mapset.Set[string]),
		description:           description,
	}
}

// AssignmentParameterComboExists checks if a given assignment name and parameter name combination
// exists in the DefaultPolicyAssignmentValues. It iterates through each assignment in the
// DefaultPolicyAssignmentValues and checks if the assignment contains the specified assignment
// name. If the assignment contains the assignment name, it then checks
// if the assignment's parameters contain the specified parameter name.
// If the combination exists, it returns true. Otherwise, it returns false.
func (d DefaultPolicyAssignmentValues) AssignmentParameterComboExists(
	wantAssignmentName, wantParameterName string,
) bool {
	for _, assignment := range d {
		if parameters, exists := assignment.assignment2Parameters[wantAssignmentName]; exists &&
			parameters.Contains(wantParameterName) {
			return true
		}
	}

	return false
}

// Add adds a new default policy assignment value to the DefaultPolicyAssignmentValues.
// It takes the defaultName, assignmentName, and parameterNames as input parameters.
// If the defaultName does not exist in the DefaultPolicyAssignmentValues, it creates a new entry.
// If the assignmentName does not exist under the defaultName, it creates a new entry.
// Finally, it appends the parameterNames to the assignmentName.
func (d DefaultPolicyAssignmentValues) Add(
	defaultName, assignmentName, description string,
	parameterNames ...string,
) {
	if _, exists := d[defaultName]; !exists {
		d[defaultName] = NewDefaultPolicyAssignmentValuesValue(description)
	}

	if _, exists := d[defaultName].assignment2Parameters[assignmentName]; !exists {
		d[defaultName].assignment2Parameters[assignmentName] = mapset.NewThreadUnsafeSet[string]()
	}

	d[defaultName].assignment2Parameters[assignmentName].Append(parameterNames...)
}

func (d DefaultPolicyAssignmentValuesValue) copy() DefaultPolicyAssignmentValuesValue {
	newVal := NewDefaultPolicyAssignmentValuesValue(d.description)

	for k, v := range d.assignment2Parameters {
		newVal.assignment2Parameters[k] = v.Clone()
	}

	return newVal
}

// Assignments returns a sorted list of assignment names.
func (d DefaultPolicyAssignmentValuesValue) Assignments() []string {
	result := make([]string, 0, len(d.assignment2Parameters))
	for s := range maps.Keys(d.assignment2Parameters) {
		result = append(result, s)
	}

	slices.Sort(result)

	return result
}

// AssignmentParameters returns a sorted list of parameter names.
func (d DefaultPolicyAssignmentValuesValue) AssignmentParameters(name string) []string {
	if _, ok := d.assignment2Parameters[name]; !ok {
		return nil
	}

	v := d.assignment2Parameters[name]
	s := v.ToSlice()
	slices.Sort(s)

	return s
}

// Description returns the description of the DefaultPolicyAssignmentValuesValue.
func (d DefaultPolicyAssignmentValuesValue) Description() string {
	return d.description
}

// PolicyAssignment2ParameterMap returns the map of assignment names to parameter names.
func (d DefaultPolicyAssignmentValuesValue) PolicyAssignment2ParameterMap() map[string]mapset.Set[string] {
	return d.assignment2Parameters
}
