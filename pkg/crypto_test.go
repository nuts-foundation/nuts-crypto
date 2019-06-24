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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
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
	defer emptyTemp(t.Name())
	client := defaultBackend(t.Name())

	t.Run("A new key pair is stored at config location", func(t *testing.T) {
		err := client.GenerateKeyPairFor(types.LegalEntity{"urn:oid:2.16.840.1.113883.2.4.6.1:00000000"})

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}
	})

	t.Run("Missing legalEntity generates error", func(t *testing.T) {
		err := client.GenerateKeyPairFor(types.LegalEntity{})

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		expected := "Missing legalEntity URI"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})

	t.Run("A keySize too small generates an error", func(t *testing.T) {
		client := Crypto{
			Storage: createTempStorage(t.Name()),
			Config:  CryptoConfig{Keysize: 1},
		}

		err := client.GenerateKeyPairFor(types.LegalEntity{"urn:oid:2.16.840.1.113883.2.4.6.1:00000000"})

		if err == nil {
			t.Errorf("Expected error got nothing")
		} else if err.Error() != "crypto/rsa: too few primes of given length to generate an RSA key" {
			t.Errorf("Expected error [crypto/rsa: too few primes of given length to generate an RSA key] got: [%s]", err.Error())
		}
	})
}

func TestCrypto_DecryptCipherTextFor(t *testing.T) {
	defer emptyTemp(t.Name())
	client := defaultBackend(t.Name())

	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
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
		_, err := client.decryptCipherTextFor([]byte(""), types.LegalEntity{URI: "other"})
		expected := "could not open private key for legalEntity: {other} with filename temp/TestCrypto_DecryptCipherTextFor/b3RoZXI=_private.pem"

		if err.Error() != expected {
			t.Errorf("Expected error [%s], Got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_encryptPlainTextFor(t *testing.T) {
	client := defaultBackend(t.Name())
	defer emptyTemp(t.Name())

	t.Run("encryption for unknown legalEntity gives error", func(t *testing.T) {
		legalEntity := types.LegalEntity{URI: "testEncrypt"}
		plaintext := "for your eyes only"

		_, err := client.encryptPlainTextFor([]byte(plaintext), legalEntity)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
			return
		}

		expected := "could not open private key for legalEntity: {testEncrypt} with filename temp/TestCrypto_encryptPlainTextFor/dGVzdEVuY3J5cHQ=_private.pem"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], Got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_DecryptKeyAndCipherTextFor(t *testing.T) {
	client := defaultBackend(t.Name())
	legalEntity := types.LegalEntity{URI: "testDecrypt"}
	client.GenerateKeyPairFor(legalEntity)
	defer emptyTemp(t.Name())

	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		plaintext := "for your eyes only"

		pubKey, _ := client.PublicKey(legalEntity)
		encRecord, err := client.EncryptKeyAndPlainTextWith([]byte(plaintext), []string{pubKey})

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
			return
		}

		decryptedText, err := client.DecryptKeyAndCipherTextFor(encRecord, legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if string(decryptedText) != plaintext {
			t.Errorf("Expected decrypted text to match [%s], Got [%s]", plaintext, decryptedText)
		}
	})

	t.Run("Incorrect cipher returns error", func(t *testing.T) {
		ct := types.DoubleEncryptedCipherText{
			CipherTextKeys: [][]byte{
				{},
			},
		}
		_, err := client.DecryptKeyAndCipherTextFor(ct, legalEntity)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		expected := "crypto/rsa: decryption error"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})

	t.Run("Missing pub key returns error", func(t *testing.T) {
		_, symkey, _ := generateSymmetricKey()
		cipherText, _, _ := encryptWithSymmetricKey([]byte("test"), symkey)

		ct := types.DoubleEncryptedCipherText{
			CipherTextKeys: [][]byte{
				cipherText,
			},
		}
		_, err := client.DecryptKeyAndCipherTextFor(ct, types.LegalEntity{URI: "testU"})

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		expected := "could not open private key for legalEntity: {testU} with filename temp/TestCrypto_DecryptKeyAndCipherTextFor/dGVzdFU=_private.pem"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})

	t.Run("Broken cipher text returns error", func(t *testing.T) {
		_, symkey, _ := generateSymmetricKey()
		cipherTextKey, _, _ := encryptWithSymmetricKey([]byte("test"), symkey)
		pk, _ := client.Storage.GetPublicKey(legalEntity)
		cipherText, _ := client.encryptPlainTextWith(cipherTextKey, pk)

		ct := types.DoubleEncryptedCipherText{
			CipherTextKeys: [][]byte{
				cipherTextKey,
			},
			CipherText: cipherText[1:],
		}
		_, err := client.DecryptKeyAndCipherTextFor(ct, legalEntity)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		expected := "crypto/rsa: decryption error"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})

	t.Run("Incorrect number of cipherTextKeys returns error", func(t *testing.T) {
		_, symkey, _ := generateSymmetricKey()
		cipherTextKey, _, _ := encryptWithSymmetricKey([]byte("test"), symkey)
		pk, _ := client.Storage.GetPublicKey(legalEntity)
		cipherText, _ := client.encryptPlainTextWith(cipherTextKey, pk)

		ct := types.DoubleEncryptedCipherText{
			CipherTextKeys: [][]byte{
				cipherTextKey,
				cipherTextKey,
			},
			CipherText: cipherText,
		}
		_, err := client.DecryptKeyAndCipherTextFor(ct, legalEntity)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		expected := "unsupported count of CipherTextKeys: 2"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_VerifyWith(t *testing.T) {
	t.Run("A signed piece of data can be verified", func(t *testing.T) {
		data := []byte("hello")
		legalEntity := types.LegalEntity{URI: "test"}
		client := defaultBackend(t.Name())
		client.GenerateKeyPairFor(legalEntity)
		defer emptyTemp(t.Name())

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
	defer emptyTemp(t.Name())
	client := defaultBackend(t.Name())

	t.Run("ExternalId creates same Id for given identifier and legalEntity", func(t *testing.T) {
		legalEntity := types.LegalEntity{URI: "testE"}
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
		legalEntity := types.LegalEntity{URI: "test2"}
		subject := "test_patient"

		_, err := client.ExternalIdFor([]byte(subject), legalEntity)

		if err == nil {
			t.Errorf("Expected error, got nothing")
		}

		expected := "could not open private key for legalEntity: {test2} with filename temp/TestCrypto_ExternalIdFor/dGVzdDI=_private.pem"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], Got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_PublicKey(t *testing.T) {
	t.Run("A signed piece of data can be verified", func(t *testing.T) {
		legalEntity := types.LegalEntity{URI: "testPK"}
		client := defaultBackend(t.Name())
		client.GenerateKeyPairFor(legalEntity)
		defer emptyTemp(t.Name())

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
		e := defaultBackend(t.Name())
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
	client := defaultBackend(t.Name())

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

func TestCrypto_encryptPlainTextWith(t *testing.T) {
	client := defaultBackend(t.Name())

	t.Run("incorrect public key returns error", func(t *testing.T) {
		plainText := "Secret"
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		pub := key.PublicKey
		pub.E = 0

		_, err = client.encryptPlainTextWith([]byte(plainText), &pub)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
			return
		}

		expected := "crypto/rsa: public exponent too small"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_pemToPublicKey(t *testing.T) {
	t.Run("wrong PEM block gives error", func(t *testing.T) {
		_, err := pemToPublicKey([]byte{})

		if err == nil {
			t.Errorf("Expected error, Got nothing")
			return
		}

		expected := "failed to decode PEM block containing public key"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})

	t.Run("wrong pub key gives error", func(t *testing.T) {
		_, err := pemToPublicKey([]byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS\n+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS\nEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n\noLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v\nTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu\nlmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26\nZQIDAQAB\n-----END PUBLIC KEY-----"))

		if err == nil {
			t.Errorf("Expected error, Got nothing")
			return
		}

		// returned error is long and complex....
	})
}

func defaultBackend(name string) Crypto {
	backend := Crypto{
		Storage: createTempStorage(name),
		Config:  CryptoConfig{Keysize: types.ConfigKeySizeDefault},
	}

	return backend
}

func createTempStorage(name string) storage.Storage {
	b, _ := storage.NewFileSystemBackend(fmt.Sprintf("temp/%s", name))
	return b
}

func emptyTemp(name string) {
	err := os.RemoveAll(fmt.Sprintf("temp/%s", name))

	if err != nil {
		println(err.Error())
	}
}
