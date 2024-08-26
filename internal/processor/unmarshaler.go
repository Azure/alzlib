// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type unmarshaler struct {
	d   []byte
	ext string
}

func newUnmarshaler(data []byte, ext string) unmarshaler {
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return unmarshaler{
		d:   data,
		ext: ext,
	}
}

func (u unmarshaler) unmarshal(dst any) error {
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
	return json.Unmarshal(data, dst)
}

func unmarshalYAML(data []byte, dst any) error {
	return yaml.Unmarshal(data, dst)
}
