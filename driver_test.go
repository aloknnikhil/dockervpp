package dockervpp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun(t *testing.T) {
	var err error

	err = Client.Run("root", "")
	Client.Wait()
	if assert.Nil(t, err) {
		err = Client.Close()
		assert.Nil(t, err)
	}
}
