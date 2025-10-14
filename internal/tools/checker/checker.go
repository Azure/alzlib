// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checker

import (
	"io"
	"os"

	"github.com/hashicorp/go-multierror"
)

// Validator is a struct that holds a list of checks to be performed.
type Validator struct {
	checks []ValidatorCheck
	quiet  bool // whether to suppress check start/finish messages
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
type ValidateFunc func() error

// NewValidator creates a new Validator with the given checks.
func NewValidator(c ...ValidatorCheck) Validator {
	return Validator{
		checks: c,
	}
}

// NewValidatorQuiet creates a new Validator with the given checks, which suppresses check start/finish messages.
func NewValidatorQuiet(c ...ValidatorCheck) Validator {
	return Validator{
		checks: c,
		quiet:  true,
	}
}

// AddChecks adds additional checks to the Validator.
func (v Validator) AddChecks(c ...ValidatorCheck) Validator {
	v.checks = append(v.checks, c...)
	return v
}

// Validate runs all the checks in the Validator against the provided resource.
func (v Validator) Validate() error {
	var errs error

	for _, c := range v.checks {
		if !v.quiet {
			io.WriteString(os.Stdout, "==> Starting check: "+c.name+"\n") // nolint: errcheck
		}

		if err := c.f(); err != nil {
			errs = multierror.Append(errs, err)
		}

		if !v.quiet {
			io.WriteString(os.Stdout, "==> Finished check: "+c.name+"\n") // nolint: errcheck
		}
	}

	return errs
}
