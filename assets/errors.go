// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import "fmt"

var _ error = (*ErrPropertyMustNotBeNil)(nil)
var _ error = (*ErrPropertyLength)(nil)

// ErrPropertyMustNotBeNil is an error type that indicates a required property is nil.
type ErrPropertyMustNotBeNil struct {
	PropertyName string
}

// Error implements the error interface for type ErrPropertyMustNotBeNil.
func (e *ErrPropertyMustNotBeNil) Error() string {
	return fmt.Sprintf("property '%s' must not be nil", e.PropertyName)
}

// NewErrPropertyMustNotBeNil creates a new ErrPropertyMustNotBeNil error.
func NewErrPropertyMustNotBeNil(propertyName string) error {
	return &ErrPropertyMustNotBeNil{PropertyName: propertyName}
}

// ErrPropertyLength is an error type that indicates a property has an invalid length.
type ErrPropertyLength struct {
	PropertyName string
	MinLength    int
	MaxLength    int
	ActualLength int
}

// Error implements the error interface for type ErrPropertyLength.
func (e *ErrPropertyLength) Error() string {
	return fmt.Sprintf("property '%s' length must be between %d and %d, but is %d",
		e.PropertyName, e.MinLength, e.MaxLength, e.ActualLength)
}

// NewErrPropertyLength creates a new ErrPropertyLength error.
func NewErrPropertyLength(propertyName string, minLength, maxLength, actualLength int) error {
	return &ErrPropertyLength{
		PropertyName: propertyName,
		MinLength:    minLength,
		MaxLength:    maxLength,
		ActualLength: actualLength,
	}
}
