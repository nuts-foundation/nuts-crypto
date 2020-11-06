package client

import (
	"github.com/nuts-foundation/nuts-crypto/api"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestNewCryptoClient_ServerMode(t *testing.T) {
	_, ok := NewCryptoClient().(*pkg.Crypto)
	assert.True(t, ok)
}

func TestNewCryptoClient_ClientMode(t *testing.T) {
	os.Setenv("NUTS_MODE", "cli")
	defer os.Unsetenv("NUTS_MODE")
	core.NutsConfig().Load(&cobra.Command{})
	_, ok := NewCryptoClient().(api.HttpClient)
	assert.True(t, ok)
}
