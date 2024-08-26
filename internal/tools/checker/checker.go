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

func NewValidatorCheck(name string, f ValidateFunc) ValidatorCheck {
	return ValidatorCheck{
		name: name,
		f:    f,
	}
}

type ValidateFunc func(any) error

func NewValidator(c ...ValidatorCheck) Validator {
	return Validator{
		checks: c,
	}
}

func (v Validator) AddChecks(c ...ValidatorCheck) Validator {
	v.checks = append(v.checks, c...)
	return v
}

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
