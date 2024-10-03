// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"maps"
	"slices"

	mapset "github.com/deckarep/golang-set/v2"
)

// PolicyAssignmentsParameterValues is a map of default names to DefaultPolicyAssignmentValuesValue.
// It is used to map a single value to multiple policy assignments.
type DefaultPolicyAssignmentValues map[string]DefaultPolicyAssignmentValuesValue

// DefaultPolicyAssignmentValuesValue is a map of assignments names to parameter names.
type DefaultPolicyAssignmentValuesValue map[string]mapset.Set[string]

// AssignmentParameterComboExists checks if a given assignment name and parameter name combination exists in the DefaultPolicyAssignmentValues.
// It iterates through each assignment in the DefaultPolicyAssignmentValues and checks if the assignment contains the specified assignment name.
// If the assignment contains the assignment name, it then checks if the assignment's parameters contain the specified parameter name.
// If the combination exists, it returns true. Otherwise, it returns false.
func (d DefaultPolicyAssignmentValues) AssignmentParameterComboExists(wantAssignmentName, wantParameterName string) bool {
	for _, assignment := range d {
		if parameters, exists := assignment[wantAssignmentName]; exists && parameters.Contains(wantParameterName) {
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
func (d DefaultPolicyAssignmentValues) Add(defaultName, assignmentName string, parameterNames ...string) {
	if _, exists := d[defaultName]; !exists {
		d[defaultName] = make(DefaultPolicyAssignmentValuesValue)
	}
	if _, exists := d[defaultName][assignmentName]; !exists {
		d[defaultName][assignmentName] = mapset.NewThreadUnsafeSet[string]()
	}
	d[defaultName][assignmentName].Append(parameterNames...)
}

func (d DefaultPolicyAssignmentValuesValue) copy() DefaultPolicyAssignmentValuesValue {
	newVal := make(DefaultPolicyAssignmentValuesValue)
	for k, v := range d {
		newVal[k] = v.Clone()
	}
	return newVal
}

// Assignments returns a sorted list of assignment names.
func (d DefaultPolicyAssignmentValuesValue) Assignments() []string {
	result := make([]string, 0, len(d))
	for s := range maps.Keys(d) {
		result = append(result, s)
	}
	slices.Sort(result)
	return result
}

// Assignments returns a sorted list of parameter names.
func (d DefaultPolicyAssignmentValuesValue) AssignmentParameters(name string) []string {
	if _, ok := d[name]; !ok {
		return nil
	}
	v := d[name]
	s := v.ToSlice()
	slices.Sort(s)
	return s
}
