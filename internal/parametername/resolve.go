// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Package parametername resolves Azure Policy parameter names against the maps that contain them.
//
// Azure Resource Manager treats template function parameters as case-insensitive and Azure Policy
// artifacts rely on this, e.g. the built-in Windows AMA/DCR initiative passes `DcrResourceId` to a
// policy definition that declares `dcrResourceId`. Go maps are case-sensitive, so an exact key
// lookup rejects artifacts that Azure itself accepts.
package parametername

import (
	"fmt"
	"slices"
	"strings"
)

// Match is a successfully resolved parameter.
// Key is the canonical key as declared by the source artifact, which may differ in case from the
// requested name.
type Match[V any] struct {
	Key   string
	Value V
}

// Resolve looks up name in values, preferring an exact match and falling back to a unique
// case-insensitive match. The boolean return value reports whether a match was found.
//
// An error is returned when the case-insensitive fallback matches more than one key, as the
// result would otherwise depend on Go map iteration order.
func Resolve[V any](values map[string]V, name string) (Match[V], bool, error) {
	if value, ok := values[name]; ok {
		return Match[V]{Key: name, Value: value}, true, nil
	}

	var candidates []string

	for key := range values {
		if strings.EqualFold(key, name) {
			candidates = append(candidates, key)
		}
	}

	switch len(candidates) {
	case 0:
		return Match[V]{}, false, nil
	case 1:
		key := candidates[0]

		return Match[V]{Key: key, Value: values[key]}, true, nil
	}

	slices.Sort(candidates)

	return Match[V]{}, false, fmt.Errorf(
		"parameter name `%s` is ambiguous, it matches `%s` when compared case-insensitively",
		name,
		strings.Join(candidates, "`, `"),
	)
}
