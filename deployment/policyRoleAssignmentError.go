package deployment

import (
	"fmt"
	"strings"
)

var _ error = &PolicyRoleAssignmentError{}
var _ error = &PolicyRoleAssignmentErrors{}

type PolicyRoleAssignmentError struct {
	assignmentName            string
	assignmentScope           string
	definitionParameterName   string
	policyDefinitionReference string
	roleDefinitionIds         []string
}

type PolicyRoleAssignmentErrors struct {
	errors []*PolicyRoleAssignmentError
}

func NewPolicyRoleAssignmentError(assignmentName string, assignmentScope string, defParameterName string, pdref string, roleDefinitionIds []string) *PolicyRoleAssignmentError {
	return &PolicyRoleAssignmentError{
		assignmentName:            assignmentName,
		assignmentScope:           assignmentScope,
		definitionParameterName:   defParameterName,
		policyDefinitionReference: pdref,
		roleDefinitionIds:         roleDefinitionIds,
	}
}

func NewPolicyRoleAssignmentErrors() *PolicyRoleAssignmentErrors {
	e := new(PolicyRoleAssignmentErrors)
	e.errors = make([]*PolicyRoleAssignmentError, 0)
	return e
}

func (e *PolicyRoleAssignmentError) Error() string {
	return fmt.Sprintf(
		"PolicyRoleAssignmentError: could not generate role assignment for assignment `%s` assigned at scope `%s`. A new role assignment should be created at scope of the definition referenced by `%s`, using parameter name `%s`, for the following role definition ids: `%s`",
		e.assignmentName,
		e.assignmentScope,
		e.policyDefinitionReference,
		e.definitionParameterName,
		strings.Join(e.roleDefinitionIds, ", "),
	)
}

func (e *PolicyRoleAssignmentErrors) Add(err ...*PolicyRoleAssignmentError) {
	e.errors = append(e.errors, err...)
}

func (e *PolicyRoleAssignmentErrors) Error() string {
	errors := make([]string, len(e.errors))
	for i, err := range e.errors {
		errors[i] = err.Error()
	}
	return strings.Join(errors, "\n")
}

func (e *PolicyRoleAssignmentErrors) Errors() []*PolicyRoleAssignmentError {
	return e.errors
}
