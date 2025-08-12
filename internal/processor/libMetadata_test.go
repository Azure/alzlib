// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package processor

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLibMetadataUnmarshal(t *testing.T) {
	input := `
  {
    "name": "test",
    "display_name": "Test",
    "description": "This is a test",
    "dependencies": [
      {
        "path": "dep1",
        "ref": "2024.03.0"
      },
      {
        "path": "dep2",
        "ref": "2024.03.0"
      }
    ]
  }`
	expected := LibMetadata{
		Name:        "test",
		DisplayName: "Test",
		Description: "This is a test",
		Dependencies: []LibMetadataDependency{
			{
				Path: "dep1",
				Ref:  "2024.03.0",
			},
			{
				Path: "dep2",
				Ref:  "2024.03.0",
			},
		},
	}

	// Test unmarshaling valid input
	var actual LibMetadata

	err := json.Unmarshal([]byte(input), &actual)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	assert.Equal(t, expected, actual)

	// Test unmarshaling empty input
	emptyInput := `{}`
	expectedEmpty := LibMetadata{}

	var actualEmpty LibMetadata
	err = json.Unmarshal([]byte(emptyInput), &actualEmpty)
	require.NoError(t, err)

	assert.Equalf(
		t,
		expectedEmpty,
		actualEmpty,
		"Expected %+v, but got %+v",
		expectedEmpty,
		actualEmpty,
	)

	// Test unmarshaling invalid input
	invalidInput := `
  {
    "name": "test",
    "display_name": "Test",
    "description": "This is a test",
    "dependencies": "invalid"
  }`

	var actualInvalid LibMetadata
	err = json.Unmarshal([]byte(invalidInput), &actualInvalid)
	require.Error(t, err)
}
