// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package errcheck

import "fmt"

var _ error = (*ChekerError)(nil)

// ChekerError is a custom error type that aggregates multiple errors.
type ChekerError struct {
	errs []error
}

// NewCheckerError creates a new instance of ChekerError with an empty list of errors.
func NewCheckerError() *ChekerError {
	return &ChekerError{
		errs: make([]error, 0),
	}
}

// Add appends an error to the ChekerError's list of errors.
func (v *ChekerError) Add(err error) {
	if err == nil {
		return
	}

	v.errs = append(v.errs, err)
}

// HasErrors checks if there are any errors in the ChekerError's list.
func (v *ChekerError) HasErrors() bool {
	return len(v.errs) > 0
}

// Error implements the error interface for ChekerError.
func (v *ChekerError) Error() string {
	if len(v.errs) == 0 {
		panic("no errors")
	}

	return fmt.Sprintf("The following errors occurred: %v", v.errs)
}
