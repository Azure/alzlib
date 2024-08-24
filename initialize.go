package alzlib

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/Azure/alzlib/pkg/processor"
)

func Thing(ctx context.Context, destinationDir string, f fs.FS, fss []fs.FS) error {
	pscl := processor.NewProcessorClient(f)
	libmeta, err := pscl.Metadata()
	if err != nil {
		return fmt.Errorf("could not get library metadata: %w", err)
	}
	meta := NewMetadata(libmeta)
	return nil
}
