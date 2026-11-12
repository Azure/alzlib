// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package environment

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLibraryStoreEnabled(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "", want: false},
		{value: "true", want: true},
		{value: "TRUE", want: true},
		{value: "1", want: true},
		{value: "false", want: false},
		{value: "0", want: false},
		{value: "yes", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(libraryStoreEnabledEnv, tc.value)
			assert.Equal(t, tc.want, LibraryStoreEnabled())
		})
	}
}
