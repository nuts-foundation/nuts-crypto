/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-crypto/test"
)

func TestCrypto_DecryptCipherTextFor(t *testing.T) {
	createCrypto(t)

	client := createCrypto(t)
	client.Config.Keysize = MinRSAKeySize // required for RSA OAEP encryption

	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		key := types.KeyForEntity(types.LegalEntity{URI: "test"})
		plaintext := "for your eyes only"

		client.GenerateKeyPair(key, false)

		cipherText, err := client.encryptPlainTextFor([]byte(plaintext), key)
		if !assert.NoError(t, err) {
			return
		}

		decryptedText, err := client.decryptCipherTextFor(cipherText, key)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, plaintext, string(decryptedText))
	})

	t.Run("decryption for unknown legalEntity gives error", func(t *testing.T) {
		_, err := client.decryptCipherTextFor([]byte(""), types.KeyForEntity(types.LegalEntity{URI: "other"}))

		assert.True(t, errors.Is(err, storage.ErrNotFound))
	})
}

func TestCrypto_encryptPlainTextFor(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	t.Run("encryption for unknown legalEntity gives error", func(t *testing.T) {
		key := types.KeyForEntity(types.LegalEntity{URI: "testEncrypt"})
		plaintext := "for your eyes only"

		_, err := client.encryptPlainTextFor([]byte(plaintext), key)

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})
}

func TestCrypto_EncryptKeyAndPlainTextWith(t *testing.T) {
	createCrypto(t)

	client := createCrypto(t)
	t.Run("returns error for unsupported algorithm", func(t *testing.T) {
		plaintext := "for your eyes only"

		sKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pKey, _ := jwk.New(sKey.Public())
		_, err := client.EncryptKeyAndPlainText([]byte(plaintext), []jwk.Key{pKey})

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "invalid algorithm for public key")
		}
	})
}

func TestCrypto_DecryptKeyAndCipherTextFor(t *testing.T) {
	client := createCrypto(t)
	client.Config.Keysize = MinRSAKeySize // required for RSA OAEP encryption
	createCrypto(t)

	client.GenerateKeyPair(key, false)

	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		plaintext := "for your eyes only"

		pubKey, _ := client.GetPublicKeyAsJWK(key)
		encRecord, err := client.EncryptKeyAndPlainText([]byte(plaintext), []jwk.Key{pubKey})

		if assert.NoError(t, err) {
			decryptedText, err := client.DecryptKeyAndCipherText(encRecord, key)

			if assert.NoError(t, err) {
				assert.Equal(t, plaintext, string(decryptedText))
			}
		}
	})

	t.Run("Incorrect cipher returns error", func(t *testing.T) {
		ct := types.DoubleEncryptedCipherText{
			CipherTextKeys: [][]byte{
				{},
			},
		}
		_, err := client.DecryptKeyAndCipherText(ct, key)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		if !errors.Is(err, rsa.ErrDecryption) {
			t.Errorf("Expected error [%v], got [%v]", rsa.ErrDecryption, err)
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
		_, err := client.DecryptKeyAndCipherText(ct, key.WithQualifier("missing"))

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})

	t.Run("Broken cipher text returns error", func(t *testing.T) {
		_, symkey, _ := generateSymmetricKey()
		cipherTextKey, _, _ := encryptWithSymmetricKey([]byte("test"), symkey)
		pk, _ := client.Storage.GetPublicKey(key)
		cipherText, _ := client.encryptPlainTextWith(cipherTextKey, pk)

		ct := types.DoubleEncryptedCipherText{
			CipherTextKeys: [][]byte{
				cipherTextKey,
			},
			CipherText: cipherText[1:],
		}
		_, err := client.DecryptKeyAndCipherText(ct, key)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		if !errors.Is(err, rsa.ErrDecryption) {
			t.Errorf("Expected error [%v], got [%v]", rsa.ErrDecryption, err)
		}
	})

	t.Run("Incorrect number of cipherTextKeys returns error", func(t *testing.T) {
		_, symkey, _ := generateSymmetricKey()
		cipherTextKey, _, _ := encryptWithSymmetricKey([]byte("test"), symkey)
		pk, _ := client.Storage.GetPublicKey(key)
		cipherText, _ := client.encryptPlainTextWith(cipherTextKey, pk)

		ct := types.DoubleEncryptedCipherText{
			CipherTextKeys: [][]byte{
				cipherTextKey,
				cipherTextKey,
			},
			CipherText: cipherText,
		}
		_, err := client.DecryptKeyAndCipherText(ct, key)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
		}

		expected := "unsupported count of CipherTextKeys: 2"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})
}

func TestCrypto_ExternalIdFor(t *testing.T) {
	createCrypto(t)

	client := createCrypto(t)
	client.GenerateKeyPair(key, false)

	t.Run("ExternalId creates same Id for given identifier and key", func(t *testing.T) {
		subject := "test_patient"
		actor := "test_actor"

		bytes1, err := client.CalculateExternalId(subject, actor, key)
		bytes2, err := client.CalculateExternalId(subject, actor, key)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if !reflect.DeepEqual(bytes1, bytes2) {
			t.Errorf("Expected externalIds to be equals")
		}
	})

	t.Run("ExternalId generates error for unknown key", func(t *testing.T) {
		subject := "test_patient"
		actor := "test_actor"

		_, err := client.CalculateExternalId(subject, actor, key.WithQualifier("unknown"))

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})

	t.Run("ExternalId generates error for missing subject", func(t *testing.T) {
		_, err := client.CalculateExternalId("", "", key)

		if err == nil {
			t.Errorf("Expected error, got nothing")
			return
		}

		if !errors.Is(err, ErrMissingSubject) {
			t.Errorf("Expected error [%v], Got [%v]", ErrMissingSubject, err)
		}
	})

	t.Run("ExternalId generates error for missing actor", func(t *testing.T) {
		_, err := client.CalculateExternalId("subject", "", key)

		if err == nil {
			t.Errorf("Expected error, got nothing")
			return
		}

		if !errors.Is(err, ErrMissingActor) {
			t.Errorf("Expected error [%v], Got [%v]", ErrMissingActor, err)
		}
	})
}

func TestCrypto_decryptWithSymmetricKey(t *testing.T) {
	t.Run("nonce empty", func(t *testing.T) {
		_, err := decryptWithSymmetricKey(make([]byte, 0), nil, make([]byte, 0))
		assert.EqualErrorf(t, err, ErrIllegalNonce.Error(), "error")
	})
}

func TestCrypto_encryptPlainTextWith(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	t.Run("incorrect public key returns error", func(t *testing.T) {
		plainText := "Secret"
		key := test.GenerateRSAKey()
		pub := key.PublicKey
		pub.E = 0

		_, err := client.encryptPlainTextWith([]byte(plainText), &pub)

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

func Test_symmetricKeyToBlockCipher(t *testing.T) {
	t.Run("error - invalid key size", func(t *testing.T) {
		c, err := symmetricKeyToBlockCipher([]byte{1, 2, 3})
		assert.Nil(t, c)
		assert.EqualError(t, err, "crypto/aes: invalid key size 3")
	})
}
