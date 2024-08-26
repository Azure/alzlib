package alzlib

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchLibraryByGetterString(t *testing.T) {
	ctx := context.Background()
	dstDir := "test-library"
	defer os.RemoveAll(filepath.Join(".alzlib", dstDir))

	fs, err := FetchLibraryByGetterString(ctx, "./testdata/simple", dstDir)
	assert.NoError(t, err)
	assert.NotNil(t, fs)
}
