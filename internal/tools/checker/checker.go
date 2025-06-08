// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checker

import (
	"io"
	"os"

	"github.com/Azure/alzlib/internal/tools/errcheck"
)

type Validator struct {
	checks []ValidatorCheck
}

type ValidatorCheck struct {
	name string
	f    ValidateFunc
}

// NewValidatorCheck creates a new ValidatorCheck with the given name and function.
// The function should return an error if the check fails, or nil if it passes.
// Use closures and a constructor function, with necessary inputs to create the ValidateFunc.
func NewValidatorCheck(name string, f ValidateFunc) ValidatorCheck {
	return ValidatorCheck{
		name: name,
		f:    f,
	}
}

// ValidateFunc is a function type that performs a validation check.
// use closures and a constructor function, with necessary inputs to create the ValidateFunc.
type ValidateFunc func() error

func NewValidator(c ...ValidatorCheck) Validator {
	return Validator{
		checks: c,
	}
}

func (v Validator) AddChecks(c ...ValidatorCheck) Validator {
	v.checks = append(v.checks, c...)
	return v
}

func (v Validator) Validate() error {
	errs := errcheck.NewCheckerError()
	for _, c := range v.checks {
		io.WriteString(os.Stdout, "==> Starting check: "+c.name+"\n") // nolint: errcheck
		if err := c.f(); err != nil {
			errs.Add(err)
		}
		io.WriteString(os.Stdout, "==> Finished check: "+c.name+"\n") // nolint: errcheck
	}
	if errs.HasErrors() {
		return errs
	}
	return nil
}
