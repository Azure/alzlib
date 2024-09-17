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
