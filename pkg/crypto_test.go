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
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"os"
	"reflect"
	"testing"
)

func TestCryptoBackend(t *testing.T) {
	t.Run("CryptoInstance always returns same instance", func(t *testing.T) {
		client := CryptoInstance()
		client2 := CryptoInstance()

		if client != client2 {
			t.Error("Expected instances to be the same")
		}
	})

	t.Run("CryptoInstance with default keysize", func(t *testing.T) {
		client := CryptoInstance()

		if client.Config.Keysize != types.ConfigKeySizeDefault {
			t.Errorf("Expected keySize to be %d, got %d", types.ConfigKeySizeDefault, client.Config.Keysize)
		}
	})
}

func TestDefaultCryptoBackend_GenerateKeyPair(t *testing.T) {
	t.Run("A new key pair is stored at config location", func(t *testing.T) {
		client := defaultBackend()
		defer emptyTemp()

		err := client.GenerateKeyPairFor(types.LegalEntity{"urn:oid:2.16.840.1.113883.2.4.6.1:00000000"})

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}
	})

	//t.Run("A new key pair is stored in the cache", func(t *testing.T) {
	//	client := createTempEngine()
	//	defer emptyTemp()
	//
	//	client.GenerateKeyPairFor(types.LegalEntity{"urn:oid:2.16.840.1.113883.2.4.6.1:00000000"})
	//
	//	entries := len(client.keyCache)
	//	if entries != 1 {
	//		t.Errorf("Expected 1 entry in cache, Got %d", entries)
	//	}
	//})

	t.Run("A keySize too small generates an error", func(t *testing.T) {
		client := Crypto{
			Storage: createTempStorage(),
			Config:  CryptoConfig{Keysize: 1},
		}

		err := client.GenerateKeyPairFor(types.LegalEntity{"urn:oid:2.16.840.1.113883.2.4.6.1:00000000"})
		defer emptyTemp()

		if err == nil {
			t.Errorf("Expected error got nothing")
		} else if err.Error() != "crypto/rsa: too few primes of given length to generate an RSA key" {
			t.Errorf("Expected error [crypto/rsa: too few primes of given length to generate an RSA key] got: [%s]", err.Error())
		}
	})
}

func TestCrypto_DecryptCipherTextFor(t *testing.T) {
	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		client := defaultBackend()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPairFor(legalEntity)

		cipherText, err := client.encryptPlainTextFor([]byte(plaintext), legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		decryptedText, err := client.decryptCipherTextFor(cipherText, legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if string(decryptedText) != plaintext {
			t.Errorf("Expected decrypted text to match [%s], Got [%s]", plaintext, decryptedText)
		}
	})

	t.Run("decryption for unknown legalEntity gives error", func(t *testing.T) {
		client := defaultBackend()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPairFor(legalEntity)

		_, err := client.encryptPlainTextFor([]byte(plaintext), legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
			return
		}

		_, err = client.decryptCipherTextFor([]byte(""), types.LegalEntity{URI: "other"})
		expected := "could not open private key for legalEntity: {other} with filename ../../temp/b3RoZXI=_private.pem"

		if err.Error() != expected {
			t.Errorf("Expected error [%s], Got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_encryptPlainTextFor(t *testing.T) {
	t.Run("encryption for unknown legalEntity gives error", func(t *testing.T) {
		client := defaultBackend()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"

		_, err := client.encryptPlainTextFor([]byte(plaintext), legalEntity)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
			return
		}

		expected := "could not open private key for legalEntity: {test} with filename ../../temp/dGVzdA==_private.pem"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], Got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_DecryptKeyAndCipherTextFor(t *testing.T) {
	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		client := defaultBackend()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPairFor(legalEntity)
		pubKey, _ := client.PublicKey(legalEntity)

		encRecord, err := client.EncryptKeyAndPlainTextWith([]byte(plaintext), []string{pubKey})

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		decryptedText, err := client.DecryptKeyAndCipherTextFor(encRecord, legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if string(decryptedText) != plaintext {
			t.Errorf("Expected decrypted text to match [%s], Got [%s]", plaintext, decryptedText)
		}
	})
}

func TestCrypto_VerifyWith(t *testing.T) {
	t.Run("A signed piece of data can be verified", func(t *testing.T) {
		data := []byte("hello")
		legalEntity := types.LegalEntity{URI: "test"}
		client := defaultBackend()
		client.GenerateKeyPairFor(legalEntity)
		defer emptyTemp()

		sig, err := client.SignFor(data, legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		pub, err := client.PublicKey(legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		bool, err := client.VerifyWith(data, sig, pub)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if !bool {
			t.Error("Expected signature to be valid")
		}
	})
}

func TestCrypto_ExternalIdFor(t *testing.T) {
	t.Run("ExternalId creates same Id for given identifier and legalEntity", func(t *testing.T) {
		client := defaultBackend()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		client.GenerateKeyPairFor(legalEntity)
		subject := "test_patient"

		bytes1, err := client.ExternalIdFor([]byte(subject), legalEntity)
		bytes2, err := client.ExternalIdFor([]byte(subject), legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if !reflect.DeepEqual(bytes1, bytes2) {
			t.Errorf("Expected externalIds to be equals")
		}
	})

	t.Run("ExternalId generates error for unknown legalEntity", func(t *testing.T) {
		client := defaultBackend()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		subject := "test_patient"

		_, err := client.ExternalIdFor([]byte(subject), legalEntity)

		if err == nil {
			t.Errorf("Expected error, got nothing")
		}

		expected := "could not open private key for legalEntity: {test} with filename ../../temp/dGVzdA==_private.pem"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], Got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_PublicKey(t *testing.T) {
	t.Run("A signed piece of data can be verified", func(t *testing.T) {
		legalEntity := types.LegalEntity{URI: "test"}
		client := defaultBackend()
		client.GenerateKeyPairFor(legalEntity)
		defer emptyTemp()

		pub, err := client.PublicKey(legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if pub == "" {
			t.Error("Expected public key, got nothing")
		}
	})
}

func TestCrypto_Configure(t *testing.T) {
	t.Run("Configure returns an error when keySize is too small", func(t *testing.T) {
		e := defaultBackend()
		e.Config.Keysize = 2047
		err := e.Configure()

		if err == nil {
			t.Errorf("Expected error, got nothing")
			return
		}

		if err.Error() != "invalid keySize, needs to be at least 2048 bits" {
			t.Errorf("Expected error [invalid keySize, needs to be at least 2048 bits], got %s", err.Error())
		}
	})
}

func TestNewCryptoBackend(t *testing.T) {
	client := defaultBackend()

	t.Run("Getting the backend returns the fs backend", func(t *testing.T) {
		cl, err := client.newCryptoStorage()

		if err != nil {
			t.Errorf("Expected no error, got %s", err.Error())
		}

		if reflect.TypeOf(cl).String() != "*storage.fileSystemBackend" {
			t.Errorf("Expected crypto backend to be of type [*storage.fileSystemBackend], Got [%s]", reflect.TypeOf(cl).String())
		}
	})

	t.Run("Getting the backend returns err for unknown backend", func(t *testing.T) {
		client.Config.Storage = "unknown"

		_, err := client.newCryptoStorage()

		if err == nil {
			t.Errorf("Expected error, got nothing")
		}

		if err.Error() != "Only fs backend available for now" {
			t.Errorf("Expected error [Only fs backend available for now], Got [%s]", err.Error())
		}
	})
}

func defaultBackend() Crypto {
	backend := Crypto{
		Storage: createTempStorage(),
		Config:  CryptoConfig{Keysize: types.ConfigKeySizeDefault},
	}

	return backend
}

func createTempStorage() storage.Storage {
	b, _ := storage.NewFileSystemBackend("../../temp")
	return b
}

func emptyTemp() {
	err := os.RemoveAll("../../temp/")

	if err != nil {
		println(err.Error())
	}
}
