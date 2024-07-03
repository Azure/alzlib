package errcheck

import (
	"errors"
	"fmt"
	"testing"
)

func TestValidateError_Error(t *testing.T) {
	err1 := errors.New("error 1")
	err2 := errors.New("error 2")
	err3 := errors.New("error 3")

	validateErr := NewCheckerError()
	validateErr.Add(err1)
	validateErr.Add(err2)
	validateErr.Add(err3)

	expected := "The following errors occurred: [error 1 error 2 error 3]"
	actual := validateErr.Error()

	if actual != expected {
		t.Errorf("Expected error message '%s', but got '%s'", expected, actual)
	}
}

func TestValidateError_ErrorPanic(t *testing.T) {
	validateErr := NewCheckerError()

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered", r)
		}
	}()

	_ = validateErr.Error()
	t.FailNow()
}
