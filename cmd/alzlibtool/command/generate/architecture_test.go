// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package generate

import (
	"context"
	"testing"
)

func TestGenerateArchitecture(t *testing.T) {
	cmd := generateArchitectureBaseCmd
	cmd.SetContext(context.Background())
	cmd.Run(&cmd, []string{"../../../../testdata/simple", "simple"})
}
