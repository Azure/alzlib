// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package to

import (
	"maps"
	"slices"
	"testing"
)

func TestValOrZeroInt(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer returns zero value", func(t *testing.T) {
		t.Parallel()

		var ptr *int
		if got := ValOrZero(ptr); got != 0 {
			t.Fatalf("ValOrZero(nil) = %d, want 0", got)
		}
	})

	t.Run("non-nil pointer returns pointed value", func(t *testing.T) {
		t.Parallel()

		value := 42
		if got := ValOrZero(&value); got != value {
			t.Fatalf("ValOrZero(&%d) = %d, want %d", value, got, value)
		}
	})
}

func TestValOrZeroString(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer returns empty string", func(t *testing.T) {
		t.Parallel()

		var ptr *string
		if got := ValOrZero(ptr); got != "" {
			t.Fatalf("ValOrZero(nil) = %q, want empty string", got)
		}
	})

	t.Run("non-nil pointer returns pointed string", func(t *testing.T) {
		t.Parallel()

		value := "hello"
		if got := ValOrZero(&value); got != value {
			t.Fatalf("ValOrZero(&%q) = %q, want %q", value, got, value)
		}
	})
}

func TestValOrZeroStruct(t *testing.T) {
	t.Parallel()

	type sample struct {
		ID   int
		Name string
	}

	t.Run("nil pointer returns zero struct", func(t *testing.T) {
		t.Parallel()

		var ptr *sample
		if got := ValOrZero(ptr); got != (sample{}) {
			t.Fatalf("ValOrZero(nil) = %+v, want zero struct", got)
		}
	})

	t.Run("non-nil pointer returns struct value", func(t *testing.T) {
		t.Parallel()

		value := sample{ID: 7, Name: "test"}
		if got := ValOrZero(&value); got != value {
			t.Fatalf("ValOrZero(&%+v) = %+v, want %+v", value, got, value)
		}
	})
}

func TestValOrZeroSlice(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer returns nil slice", func(t *testing.T) {
		t.Parallel()

		var ptr *[]string
		if got := ValOrZero(ptr); got != nil {
			t.Fatalf("ValOrZero(nil) = %#v, want nil slice", got)
		}
	})

	t.Run("non-nil pointer returns slice contents", func(t *testing.T) {
		t.Parallel()

		value := []string{"alpha", "beta"}
		if got := ValOrZero(&value); !slices.Equal(got, value) {
			t.Fatalf("ValOrZero(&%v) = %v, want %v", value, got, value)
		}
	})

	t.Run("pointer to nil slice preserves nil", func(t *testing.T) {
		t.Parallel()

		var nilSlice []string

		ptr := &nilSlice
		if got := ValOrZero(ptr); got != nil {
			t.Fatalf("ValOrZero(pointer to nil slice) = %#v, want nil slice", got)
		}
	})
}

func TestValOrZeroMap(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer returns nil map", func(t *testing.T) {
		t.Parallel()

		var ptr *map[string]int
		if got := ValOrZero(ptr); got != nil {
			t.Fatalf("ValOrZero(nil) = %#v, want nil map", got)
		}
	})

	t.Run("non-nil pointer returns map contents", func(t *testing.T) {
		t.Parallel()

		value := map[string]int{"a": 1, "b": 2}
		if got := ValOrZero(&value); !maps.Equal(got, value) {
			t.Fatalf("ValOrZero(&%v) = %v, want %v", value, got, value)
		}
	})
}
