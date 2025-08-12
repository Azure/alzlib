// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package checker

import (
	"io"
	"os"

	"github.com/Azure/alzlib/internal/tools/errcheck"
)

// Validator is a struct that holds a list of checks to be performed.
type Validator struct {
	checks []ValidatorCheck
}

// ValidatorCheck is a struct that holds the name and function of a check to be performed.
// The function should return an error if the check fails.
// Use closures to capture the context of the check, such as the resource type or other parameters.
type ValidatorCheck struct {
	name string
	f    ValidateFunc
}

// NewValidatorCheck creates a new ValidatorCheck with the given name and function.
func NewValidatorCheck(name string, f ValidateFunc) ValidatorCheck {
	return ValidatorCheck{
		name: name,
		f:    f,
	}
}

// ValidateFunc is a function type that takes an input of any type and returns an error if the validation fails.
type ValidateFunc func(any) error

// NewValidator creates a new Validator with the given checks.
func NewValidator(c ...ValidatorCheck) Validator {
	return Validator{
		checks: c,
	}
}

// AddChecks adds additional checks to the Validator.
func (v Validator) AddChecks(c ...ValidatorCheck) Validator {
	v.checks = append(v.checks, c...)
	return v
}

// Validate runs all the checks in the Validator against the provided resource.
func (v Validator) Validate(resource any) error {
	errs := errcheck.NewCheckerError()

	for _, c := range v.checks {
		io.WriteString(os.Stdout, "==> Starting check: "+c.name+"\n") // nolint: errcheck

		if err := c.f(resource); err != nil {
			errs.Add(err)
		}

		io.WriteString(os.Stdout, "==> Finished check: "+c.name+"\n") // nolint: errcheck
	}

	if errs.HasErrors() {
		return errs
	}

	return nil
}
