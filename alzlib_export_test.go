package alzlib_test

import (
	"testing"

	"github.com/matt-FFFFFF/alzlib"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

func TestNewAlzLibOptions(t *testing.T) {
	az := alzlib.NewAlzLib()
	assert.Equal(t, 10, az.Options.Parallelism)
}

func TestNewAlzLibOptionsError(t *testing.T) {
	az := new(alzlib.AlzLib)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	assert.ErrorContains(t, az.Init(ctx), "parallelism")
	az.Options = new(alzlib.AlzLibOptions)
	assert.ErrorContains(t, az.Init(ctx), "parallelism")
}
