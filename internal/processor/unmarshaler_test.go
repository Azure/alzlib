// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalJson(t *testing.T) {
	data := []byte(`{"name": "John", "age": 30}`)
	ext := ".json"
	u := newUnmarshaler(data, ext)

	var dst map[string]interface{}
	err := u.unmarshal(&dst)

	assert.NoError(t, err)
	assert.Equal(t, "John", dst["name"])
	assert.Equal(t, float64(30), dst["age"])
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

		assert.NoError(t, err)
		assert.Equal(t, "John", dst["name"])
		assert.Equal(t, int(30), dst["age"])
	}
}
