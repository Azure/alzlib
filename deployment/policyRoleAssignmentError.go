// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"fmt"
	"strings"
)

var _ error = &PolicyRoleAssignmentError{}
var _ error = &PolicyRoleAssignmentErrors{}

// PolicyRoleAssignmentError represents an error that occurred while generating a role assignment
// for a policy
// assignment.
type PolicyRoleAssignmentError struct {
	assignmentName            string
	assignmentScope           string
	definitionParameterName   string
	policyDefinitionReference string
	roleDefinitionIDs         []string
	wrappedError              error
}

// PolicyRoleAssignmentErrors represents a collection of PolicyRoleAssignmentError.
// It can be used by the caller to emit a warning rather than halt execution.
type PolicyRoleAssignmentErrors struct {
	errors []*PolicyRoleAssignmentError
}

// NewPolicyRoleAssignmentError creates a new PolicyRoleAssignmentError with the provided parameters.
func NewPolicyRoleAssignmentError(
	assignmentName string,
	assignmentScope string,
	defParameterName string,
	pdref string,
	roleDefinitionIDs []string,
	innerError error,
) *PolicyRoleAssignmentError {
	return &PolicyRoleAssignmentError{
		assignmentName:            assignmentName,
		assignmentScope:           assignmentScope,
		definitionParameterName:   defParameterName,
		policyDefinitionReference: pdref,
		roleDefinitionIDs:         roleDefinitionIDs,
		wrappedError:              innerError,
	}
}

// NewPolicyRoleAssignmentErrors creates a new PolicyRoleAssignmentErrors collection.
func NewPolicyRoleAssignmentErrors() *PolicyRoleAssignmentErrors {
	e := new(PolicyRoleAssignmentErrors)
	e.errors = make([]*PolicyRoleAssignmentError, 0)

	return e
}

// Error implements the error interface.
func (e *PolicyRoleAssignmentError) Error() string {
	return fmt.Sprintf(
		"PolicyRoleAssignmentError: could not generate role assignment for assignment `%s` assigned at scope `%s`. "+
			"A new role assignment should be created at scope of the definition referenced by `%s`, "+
			"using parameter name `%s`, for the following role definition ids: `%s`. InnerError: %v",
		e.assignmentName,
		e.assignmentScope,
		e.policyDefinitionReference,
		e.definitionParameterName,
		strings.Join(e.roleDefinitionIDs, ", "),
		e.wrappedError,
	)
}

func (e *PolicyRoleAssignmentError) Unwrap() error {
	return e.wrappedError
}

// Add adds one or more PolicyRoleAssignmentError to the collection.
func (e *PolicyRoleAssignmentErrors) Add(err ...*PolicyRoleAssignmentError) {
	e.errors = append(e.errors, err...)
}

// Error implements the error interface.
func (e *PolicyRoleAssignmentErrors) Error() string {
	errors := make([]string, len(e.errors))
	for i, err := range e.errors {
		errors[i] = err.Error()
	}

	return strings.Join(errors, "\n---\n")
}

// Errors returns the collection of PolicyRoleAssignmentError.
func (e *PolicyRoleAssignmentErrors) Errors() []*PolicyRoleAssignmentError {
	return e.errors
}
