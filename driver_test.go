package dockervpp

import (
	"narfnet/vpp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun(t *testing.T) {
	var err error

	err = vpp.Client.Run("root")
	if assert.Nil(t, err) {
		err = vpp.Client.Close()
		assert.Nil(t, err)
	}
}
