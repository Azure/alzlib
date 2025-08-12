// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalJson(t *testing.T) {
	data := []byte(`{"name": "John", "age": 30}`)
	ext := ".json"
	u := newUnmarshaler(data, ext)

	var dst map[string]interface{}

	err := u.unmarshal(&dst)

	require.NoError(t, err)
	assert.Equal(t, "John", dst["name"])
	assert.InEpsilon(t, float64(30), dst["age"], 0.01)
}

func TestUnmarshalYaml(t *testing.T) {
	data := []byte(`
name: John
age: 30
`)
	for _, ext := range []string{".yaml", ".yml"} {
		u := newUnmarshaler(data, ext)

		var dst map[string]interface{}

		err := u.unmarshal(&dst)

		require.NoError(t, err)
		assert.Equal(t, "John", dst["name"])
		assert.Equal(t, int(30), dst["age"])
	}
}
