package client

import (
	"github.com/nuts-foundation/nuts-crypto/api"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfigureCryptoClient(t *testing.T) {
	t.Run("ok - server mode", func(t *testing.T) {
		globalConfig := core.NewNutsGlobalConfig()
		globalConfig.Load(&cobra.Command{})
		client := configureClient(pkg.CryptoInstance(), globalConfig)
		assert.NotNil(t, client)
		assert.IsType(t, &pkg.Crypto{}, client)
	})
	t.Run("ok - CLI mode", func(t *testing.T) {
		client := configureClient(&pkg.Crypto{Config: pkg.DefaultCryptoConfig()}, testConfig{})
		assert.NotNil(t, client)
		assert.IsType(t, api.HttpClient{}, client)
	})
	t.Run("error - panics for illegal config", func(t *testing.T) {
		instance := &pkg.Crypto{Config: pkg.DefaultCryptoConfig()}
		instance.Config.Keysize = 1
		assert.Panics(t, func() {
			configureClient(instance, core.NutsConfig())
		})
	})
}

type testConfig struct {

}

func (t testConfig) ServerAddress() string {
	panic("implement me")
}

func (t testConfig) InStrictMode() bool {
	panic("implement me")
}

func (t testConfig) Mode() string {
	panic("implement me")
}

func (t testConfig) Identity() string {
	panic("implement me")
}

func (t testConfig) GetEngineMode(engineMode string) string {
	return "client"
}
