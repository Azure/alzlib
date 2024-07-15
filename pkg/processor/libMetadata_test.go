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
    "dependencies": ["dep1", "dep2"]
  }`
	expected := LibMetadata{
		Name:         "test",
		DisplayName:  "Test",
		Description:  "This is a test",
		Dependencies: []string{"dep1", "dep2"},
	}

	// Test unmarshaling valid input
	var actual LibMetadata
	err := json.Unmarshal([]byte(input), &actual)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	assert.EqualValues(t, expected, actual)

	// Test unmarshaling empty input
	emptyInput := `{}`
	expectedEmpty := LibMetadata{}
	var actualEmpty LibMetadata
	err = json.Unmarshal([]byte(emptyInput), &actualEmpty)
	require.NoError(t, err)

	assert.EqualValuesf(t, expectedEmpty, actualEmpty, "Expected %+v, but got %+v", expectedEmpty, actualEmpty)

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
	assert.Error(t, err)
}
