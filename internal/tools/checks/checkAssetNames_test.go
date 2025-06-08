package checks

import (
	"testing"

	"github.com/Azure/alzlib/internal/tools/filename"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAssetNames(t *testing.T) {
	dir := "testdata/filenamescorrect"
	require.NoError(t, checkAssetFileNames(dir))
}

func TestCheckAssetNamesIncorrect(t *testing.T) {
	dir := "testdata/filenamesincorrect"
	err := checkAssetFileNames(dir)
	require.Error(t, err)
	var fileNameErr *FileNameErr
	require.ErrorAs(t, err, &fileNameErr)
	assert.Len(t, fileNameErr.fileNameErrors, 7)
	for _, err := range fileNameErr.fileNameErrors {
		assert.ErrorIs(t, err, filename.ErrIncorrectFileName)
	}
}
