// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Unmarshaler struct {
	d   []byte
	ext string
}

func NewUnmarshaler(data []byte, ext string) Unmarshaler {
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	return Unmarshaler{
		d:   data,
		ext: ext,
	}
}

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

func unmarshalYAML(data []byte, dst any) error {
	return yaml.Unmarshal(data, dst) //nolint:wrapcheck
}
