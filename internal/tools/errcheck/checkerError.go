package errcheck

import "fmt"

var _ error = (*ChekerError)(nil)

type ChekerError struct {
	errs []error
}

func NewCheckerError() *ChekerError {
	return &ChekerError{
		errs: make([]error, 0),
	}
}

func (v *ChekerError) Add(err error) {
	if err == nil {
		return
	}
	v.errs = append(v.errs, err)
}

func (v *ChekerError) HasErrors() bool {
	return len(v.errs) > 0
}

func (v *ChekerError) Error() string {
	if len(v.errs) == 0 {
		panic("no errors")
	}
	return fmt.Sprintf("The following errors occurred: %v", v.errs)
}
