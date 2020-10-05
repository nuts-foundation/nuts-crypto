/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package pkg

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509/pkix"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/nuts-foundation/nuts-go-test/io"

	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/spf13/cobra"

	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/stretchr/testify/assert"
)

var extension = pkix.Extension{Id: []int{1, 2}, Critical: false, Value: []byte("test")}
var entity = types.LegalEntity{URI: "urn:oid:1.3.6.1.4.1.54851.4:123"}
var key = types.KeyForEntity(entity)

func TestCryptoBackend(t *testing.T) {
	t.Run("CryptoInstance always returns same instance", func(t *testing.T) {
		client := CryptoInstance()
		client2 := CryptoInstance()

		if client != client2 {
			t.Error("Expected instances to be the same")
		}
	})
}

func TestDefaultCryptoBackend_GenerateKeyPair(t *testing.T) {
	createCrypto(t)

	client := createCrypto(t)

	t.Run("A new key pair is stored at config location", func(t *testing.T) {
		_, err := client.GenerateKeyPair(key, false)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}
	})

	t.Run("Missing key identifier generates error", func(t *testing.T) {
		_, err := client.GenerateKeyPair(nil, false)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		if !errors.Is(err, ErrInvalidKeyIdentifier) {
			t.Errorf("Expected error [%v], got [%v]", ErrInvalidKeyIdentifier, err)
		}
	})

	t.Run("A keySize too small generates an error", func(t *testing.T) {
		client := createCrypto(t)
		client.Config.Keysize = 1

		_, err := client.GenerateKeyPair(key, false)

		if err == nil {
			t.Errorf("Expected error got nothing")
		} else if err.Error() != "crypto/rsa: too few primes of given length to generate an RSA key" {
			t.Errorf("Expected error [crypto/rsa: too few primes of given length to generate an RSA key] got: [%s]", err.Error())
		}
	})
}

func TestCrypto_SignFor(t *testing.T) {
	createCrypto(t)

	t.Run("error - private key does not exist", func(t *testing.T) {
		client := createCrypto(t)
		sig, err := client.Sign([]byte{1, 2, 3}, key)
		assert.Error(t, err)
		assert.Nil(t, sig)
	})
}

func TestCrypto_PublicKeyInPem(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)

	t.Run("Public key is returned from storage", func(t *testing.T) {
		pub, err := client.GetPublicKeyAsPEM(key)

		assert.Nil(t, err)
		assert.NotEmpty(t, pub)
	})

	t.Run("Public key for unknown entity returns error", func(t *testing.T) {
		_, err := client.GetPublicKeyAsPEM(key.WithQualifier("testtest"))

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})

	t.Run("parse public key", func(t *testing.T) {
		pub := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9wJQN59PYsvIsTrFuTqS\nLoUBgwdRfpJxOa5L8nOALxNk41MlAg7xnPbvnYrOHFucfWBTDOMTKBMSmD4WDkaF\ndVrXAML61z85Le8qsXfX6f7TbKMDm2u1O3cye+KdJe8zclK9sTFzSD0PP0wfw7wf\nlACe+PfwQgeOLPUWHaR6aDfaA64QEdfIzk/IL3S595ixaEn0huxMHgXFX35Vok+o\nQdbnclSTo6HUinkqsHUu/hGHApkE3UfT6GD6SaLiB9G4rAhlrDQ71ai872t4FfoK\n7skhe8sP2DstzAQRMf9FcetrNeTxNL7Zt4F/qKm80cchRZiFYPMCYyjQphyBCoJf\n0wIDAQAB\n-----END PUBLIC KEY-----"

		_, err := cert.PemToPublicKey([]byte(pub))

		assert.Nil(t, err)
	})
}

func TestCrypto_GetPrivateKey(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	t.Run("private key not found", func(t *testing.T) {
		pk, err := client.GetPrivateKey(key)
		assert.Nil(t, pk)
		assert.Error(t, err)
	})
	t.Run("get private key, assert non-exportable", func(t *testing.T) {
		client.GenerateKeyPair(key, false)
		pk, err := client.GetPrivateKey(key)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.NotNil(t, pk) {
			return
		}
		// Assert that we don't accidentally return the actual RSA/ECDSA key, because they should stay in the storage
		// and be non-exportable.
		_, ok := pk.(*rsa.PrivateKey)
		assert.False(t, ok)
		_, ok = pk.(*ecdsa.PrivateKey)
		assert.False(t, ok)
	})
}

func TestCrypto_KeyExistsFor(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)

	t.Run("returns true for existing key", func(t *testing.T) {
		assert.True(t, client.PrivateKeyExists(key))
	})

	t.Run("returns false for non-existing key", func(t *testing.T) {
		assert.False(t, client.PrivateKeyExists(types.KeyForEntity(types.LegalEntity{URI: "does_not_exists"})))
	})
}

func TestCrypto_GenerateKeyPair(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		publicKey, err := client.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: t.Name()}), false)
		assert.NoError(t, err)
		assert.NotNil(t, publicKey)
	})
	t.Run("ok - overwrite", func(t *testing.T) {
		publicKey, _ := client.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: t.Name()}), false)
		assert.NotNil(t, publicKey)
		publicKey2, err := client.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: t.Name()}), true)
		assert.NoError(t, err)
		assert.NotNil(t, publicKey2)
	})
	t.Run("error - already exists", func(t *testing.T) {
		publicKey, _ := client.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: t.Name()}), false)
		assert.NotNil(t, publicKey)
		publicKey2, err := client.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: t.Name()}), false)
		assert.EqualError(t, err, "key already exists")
		assert.Nil(t, publicKey2)
	})
}

func TestCrypto_doConfigure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		e := createCrypto(t)
		err := e.doConfigure()
		assert.NoError(t, err)
	})
	t.Run("ok - default = fs backend", func(t *testing.T) {
		client := createCrypto(t)
		err := client.doConfigure()
		if !assert.NoError(t, err) {
			return
		}
		storageType := reflect.TypeOf(client.Storage).String()
		assert.Equal(t, "*storage.fileSystemBackend", storageType)
	})
	t.Run("error - unknown backend", func(t *testing.T) {
		client := createCrypto(t)
		client.Config.Storage = "unknown"
		err := client.doConfigure()
		assert.EqualErrorf(t, err, "only fs backend available for now", "expected error")
	})
	t.Run("error - fs path invalid", func(t *testing.T) {
		client := createCrypto(t)
		client.Config.Fspath = "crypto.go"
		err := client.doConfigure()
		assert.EqualError(t, err, "error checking for existing truststore: stat crypto.go/truststore.pem: not a directory")
	})
	t.Run("error - keySize is too small", func(t *testing.T) {
		// Switch to strict mode just for this test
		os.Setenv("NUTS_STRICTMODE", "true")
		core.NutsConfig().Load(&cobra.Command{})
		defer core.NutsConfig().Load(&cobra.Command{})
		defer os.Unsetenv("NUTS_STRICTMODE")
		e := createCrypto(t)
		e.Config.Keysize = 2047
		err := e.doConfigure()
		assert.EqualError(t, err, ErrInvalidKeySize.Error())
	})
}

func TestCrypto_Configure(t *testing.T) {
	createCrypto(t)

	t.Run("ok - configOnce", func(t *testing.T) {
		e := createCrypto(t)
		assert.False(t, e.configDone)
		err := e.Configure()
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, e.configDone)
		err = e.Configure()
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, e.configDone)
	})
	t.Run("ok - server mode", func(t *testing.T) {
		e := createCrypto(t)
		e.Config.Keysize = 4096
		err := e.Configure()
		assert.NoError(t, err)
	})
	t.Run("ok - client mode", func(t *testing.T) {
		e := createCrypto(t)
		e.Storage = nil
		e.Config.Mode = core.ClientEngineMode
		err := e.Configure()
		assert.NoError(t, err)
		// Assert server-mode services aren't initialized in client mode
		assert.Nil(t, e.Storage)
	})
	t.Run("error - keySize is too small", func(t *testing.T) {
		e := createCrypto(t)
		assert.False(t, e.configDone)
		err := e.Configure()
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, e.configDone)
		err = e.Configure()
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, e.configDone)
	})
}

func TestCrypto_Start(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	t.Run("adds 3 certificate monitors", func(t *testing.T) {
		client.Start()
		defer client.Shutdown()

		assert.Len(t, client.certMonitors, 3)
	})
}

func createCrypto(t *testing.T) *Crypto {
	os.Setenv("NUTS_IDENTITY", entity.URI)
	if err := core.NutsConfig().Load(&cobra.Command{}); err != nil {
		panic(err)
	}
	trustStore := poolCertVerifier{}
	dir := io.TestDirectory(t)
	backend, _ := storage.NewFileSystemBackend(dir)
	crypto := Crypto{
		Storage:    backend,
		Config:     TestCryptoConfig(dir),
		trustStore: &trustStore,
	}
	crypto.Config.Keysize = 1024

	return &crypto
}
