package backend

import (
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/spf13/viper"
	"reflect"
	"testing"
)

func TestNewCryptoBackend(t *testing.T) {
	t.Run("Getting the backend returns the fs backend", func(t *testing.T) {
		viper.Set(types.ConfigBackend, types.ConfigBackendFs)

		cl, err := NewCryptoBackend()

		if err != nil {
			t.Errorf("Expected no error, got %s", err.Error())
		}

		if reflect.TypeOf(cl).String() != "*backend.fileSystemBackend" {
			t.Errorf("Expected crypto backend to be of type [*backend.fileSystemBackend], Got [%s]", reflect.TypeOf(cl).String())
		}
	})

	t.Run("Getting the backend returns err for unknown backend", func(t *testing.T) {
		viper.Set(types.ConfigBackend, "unknown")

		_, err := NewCryptoBackend()

		if err == nil {
			t.Errorf("Expected error, got nothing")
		}

		if err.Error() != "Only fs backend available for now" {
			t.Errorf("Expected error [Only fs backend available for now], Got [%s]", err.Error())
		}
	})
}