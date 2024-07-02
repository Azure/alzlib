package validation

import "fmt"

var _ error = (*ValidateError)(nil)

type ValidateError struct {
	errs []error
}

func newValidateError() *ValidateError {
	return &ValidateError{
		errs: make([]error, 0),
	}
}

func (v *ValidateError) add(err error) {
	if err == nil {
		return
	}
	v.errs = append(v.errs, err)
}

func (v *ValidateError) HasErrors() bool {
	return len(v.errs) > 0
}

func (v *ValidateError) Error() string {
	if len(v.errs) == 0 {
		panic("no errors")
	}
	return fmt.Sprintf("The following errors occured: %v", v.errs)
}
