// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Unmarshaler is a struct that unmarshals data based on the file extension.
type Unmarshaler struct {
	d   []byte
	ext string
}

// NewUnmarshaler creates a new Unmarshaler.
func NewUnmarshaler(data []byte, ext string) Unmarshaler {
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	return Unmarshaler{
		d:   data,
		ext: ext,
	}
}

// Unmarshal unmarshals the data into the provided destination based on the file extension.
func (u Unmarshaler) Unmarshal(dst any) error {
	switch strings.ToLower(u.ext) {
	case ".json":
		return unmarshalJSON(u.d, dst)
	case ".yaml":
		return unmarshalYAML(u.d, dst)
	case ".yml":
		return unmarshalYAML(u.d, dst)
	}

	return fmt.Errorf("unmarshaler.unmarshal: unsupported extension: %s", u.ext)
}

func unmarshalJSON(data []byte, dst any) error {
	return json.Unmarshal(data, dst) //nolint:wrapcheck
}

// unmarshalYAML converts the YAML document to JSON before unmarshalling it into dst.
//
// This indirection is deliberate. Many destination types are Azure SDK models
// (e.g. armauthorization.RoleDefinition), which declare only `json:"..."` struct tags and
// implement custom json.Unmarshaler methods keyed on the exact ARM field names. Decoding
// YAML straight into those types silently produces empty values, because gopkg.in/yaml.v3
// neither honours `json` tags nor invokes json.Unmarshaler. Round-tripping through JSON
// makes the YAML and JSON code paths behave identically.
func unmarshalYAML(data []byte, dst any) error {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("unmarshaler.unmarshalYAML: yaml.Unmarshal error: %w", err)
	}

	jsonBytes, err := json.Marshal(normalizeYAMLToJSON(raw))
	if err != nil {
		return fmt.Errorf("unmarshaler.unmarshalYAML: json.Marshal error: %w", err)
	}

	return unmarshalJSON(jsonBytes, dst)
}

// normalizeYAMLToJSON makes a decoded YAML value safe to marshal as JSON.
//
// yaml.v3 decodes a mapping into map[string]interface{} only when every key is a string;
// otherwise it yields map[interface{}]interface{}, which encoding/json cannot marshal.
// Converting those keys with fmt.Sprint mirrors how the same document would be written in
// JSON, where object keys are always strings.
func normalizeYAMLToJSON(value any) any {
	switch v := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(v))
		for key, val := range v {
			result[key] = normalizeYAMLToJSON(val)
		}

		return result

	case map[any]any:
		result := make(map[string]any, len(v))
		for key, val := range v {
			result[fmt.Sprint(key)] = normalizeYAMLToJSON(val)
		}

		return result

	case []any:
		result := make([]any, len(v))
		for i, val := range v {
			result[i] = normalizeYAMLToJSON(val)
		}

		return result

	default:
		return value
	}
}
