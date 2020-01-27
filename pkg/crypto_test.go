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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/stretchr/testify/assert"
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

		if !errors.Is(err, ErrMissingLegalEntityURI) {
			t.Errorf("Expected error [%v], got [%v]", ErrMissingLegalEntityURI, err)
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

		assert.True(t, errors.Is(err, storage.ErrNotFound))
	})
}

func TestCrypto_encryptPlainTextFor(t *testing.T) {
	client := defaultBackend(t.Name())
	defer emptyTemp(t.Name())

	t.Run("encryption for unknown legalEntity gives error", func(t *testing.T) {
		legalEntity := types.LegalEntity{URI: "testEncrypt"}
		plaintext := "for your eyes only"

		_, err := client.encryptPlainTextFor([]byte(plaintext), legalEntity)

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})
}

func TestCrypto_EncryptKeyAndPlainTextWith(t *testing.T) {
	client := defaultBackend(t.Name())
	t.Run("returns error for unsupported algorithm", func(t *testing.T) {
		plaintext := "for your eyes only"

		sKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pKey, _ := jwk.New(sKey.Public())
		_, err := client.EncryptKeyAndPlainTextWith([]byte(plaintext), []jwk.Key{pKey})

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "invalid algorithm for public key")
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

		pubKey, _ := client.PublicKeyInJWK(legalEntity)
		encRecord, err := client.EncryptKeyAndPlainTextWith([]byte(plaintext), []jwk.Key{pubKey})

		if assert.NoError(t, err) {
			decryptedText, err := client.DecryptKeyAndCipherTextFor(encRecord, legalEntity)

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
		_, err := client.DecryptKeyAndCipherTextFor(ct, legalEntity)

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
		_, err := client.DecryptKeyAndCipherTextFor(ct, types.LegalEntity{URI: "testU"})

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
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

		if !errors.Is(err, rsa.ErrDecryption) {
			t.Errorf("Expected error [%v], got [%v]", rsa.ErrDecryption, err)
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

		pub, err := client.PublicKeyInJWK(legalEntity)

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
	legalEntity := types.LegalEntity{URI: "testE"}
	client.GenerateKeyPairFor(legalEntity)

	t.Run("ExternalId creates same Id for given identifier and legalEntity", func(t *testing.T) {
		subject := "test_patient"
		actor := "test_actor"

		bytes1, err := client.ExternalIdFor(subject, actor, legalEntity)
		bytes2, err := client.ExternalIdFor(subject, actor, legalEntity)

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
		actor := "test_actor"

		_, err := client.ExternalIdFor(subject, actor, legalEntity)

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})

	t.Run("ExternalId generates error for missing subject", func(t *testing.T) {
		_, err := client.ExternalIdFor("", "", legalEntity)

		if err == nil {
			t.Errorf("Expected error, got nothing")
			return
		}

		if !errors.Is(err, ErrMissingSubject) {
			t.Errorf("Expected error [%v], Got [%v]", ErrMissingSubject, err)
		}
	})

	t.Run("ExternalId generates error for missing actor", func(t *testing.T) {
		_, err := client.ExternalIdFor("subject", "", legalEntity)

		if err == nil {
			t.Errorf("Expected error, got nothing")
			return
		}

		if !errors.Is(err, ErrMissingActor) {
			t.Errorf("Expected error [%v], Got [%v]", ErrMissingActor, err)
		}
	})
}

func TestCrypto_PublicKeyInPem(t *testing.T) {
	legalEntity := types.LegalEntity{URI: "testPK"}
	client := defaultBackend(t.Name())
	client.GenerateKeyPairFor(legalEntity)
	defer emptyTemp(t.Name())

	t.Run("Public key is returned from storage", func(t *testing.T) {
		pub, err := client.PublicKeyInPEM(legalEntity)

		assert.Nil(t, err)
		assert.NotEmpty(t, pub)
	})

	t.Run("Public key for unknown entity returns error", func(t *testing.T) {
		legalEntity := types.LegalEntity{URI: "testPKUnknown"}
		_, err := client.PublicKeyInPEM(legalEntity)

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})

	t.Run("parse public key", func(t *testing.T) {
		pub := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9wJQN59PYsvIsTrFuTqS\nLoUBgwdRfpJxOa5L8nOALxNk41MlAg7xnPbvnYrOHFucfWBTDOMTKBMSmD4WDkaF\ndVrXAML61z85Le8qsXfX6f7TbKMDm2u1O3cye+KdJe8zclK9sTFzSD0PP0wfw7wf\nlACe+PfwQgeOLPUWHaR6aDfaA64QEdfIzk/IL3S595ixaEn0huxMHgXFX35Vok+o\nQdbnclSTo6HUinkqsHUu/hGHApkE3UfT6GD6SaLiB9G4rAhlrDQ71ai872t4FfoK\n7skhe8sP2DstzAQRMf9FcetrNeTxNL7Zt4F/qKm80cchRZiFYPMCYyjQphyBCoJf\n0wIDAQAB\n-----END PUBLIC KEY-----"

		_, err := PemToPublicKey([]byte(pub))

		assert.Nil(t, err)
	})
}

func TestCrypto_PublicKeyInJWK(t *testing.T) {
	legalEntity := types.LegalEntity{URI: "testPK"}
	client := defaultBackend(t.Name())
	client.GenerateKeyPairFor(legalEntity)
	defer emptyTemp(t.Name())

	t.Run("Public key is returned from storage", func(t *testing.T) {
		pub, err := client.PublicKeyInJWK(legalEntity)

		assert.NoError(t, err)
		assert.NotNil(t, pub)
		assert.Equal(t, jwa.RSA, pub.KeyType())
	})

	t.Run("Public key for unknown entity returns error", func(t *testing.T) {
		legalEntity := types.LegalEntity{URI: "testPKUnknown"}
		_, err := client.PublicKeyInJWK(legalEntity)

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})
}

func TestCrypto_SignJwtFor(t *testing.T) {
	client := defaultBackend(t.Name())
	legalEntity := types.LegalEntity{URI: "testSignJwt"}
	client.GenerateKeyPairFor(legalEntity)
	defer emptyTemp(t.Name())

	t.Run("creates valid JWT", func(t *testing.T) {
		tokenString, err := client.SignJwtFor(map[string]interface{}{"iss": "nuts"}, legalEntity)

		assert.Nil(t, err)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			pubKey, _ := client.Storage.GetPublicKey(legalEntity)
			return pubKey, nil
		})

		assert.True(t, token.Valid)
		assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
	})

	t.Run("returns error for not found", func(t *testing.T) {
		_, err := client.SignJwtFor(map[string]interface{}{"iss": "nuts"}, types.LegalEntity{URI: "notFound"})

		assert.True(t, errors.Is(err, storage.ErrNotFound))
	})
}

func TestCrypto_KeyExistsFor(t *testing.T) {
	client := defaultBackend(t.Name())
	legalEntity := types.LegalEntity{URI: "exists"}
	client.GenerateKeyPairFor(legalEntity)
	defer emptyTemp(t.Name())

	t.Run("returns true for existing key", func(t *testing.T) {
		assert.True(t, client.KeyExistsFor(legalEntity))
	})

	t.Run("returns false for non-existing key", func(t *testing.T) {
		assert.False(t, client.KeyExistsFor(types.LegalEntity{URI: "does_not_exists"}))
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

		if !errors.Is(err, ErrInvalidKeySize) {
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
		_, err := PemToPublicKey([]byte{})

		if err == nil {
			t.Errorf("Expected error, Got nothing")
			return
		}

		expected := "failed to decode PEM block containing public key, key is of the wrong type"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})
}

func TestJwkToMap(t *testing.T) {
	t.Run("Generates map for RSA key", func(t *testing.T) {
		rsa, _ := rsa.GenerateKey(rand.Reader, 1024)
		jwk, _ := jwk.New(rsa)

		jwkMap, err := JwkToMap(jwk)

		if assert.NoError(t, err) {
			assert.Equal(t, jwa.KeyType("RSA"), jwkMap["kty"])
		}
	})
}

func TestMapToJwk(t *testing.T) {
	t.Run("Generates Jwk from map", func(t *testing.T) {
		jwkAsJSON := `{"d":"Ce3obeVsZeU3QaKBTQ-Qn-EaUfhEVViHbnP3gnLDrXNbiUf09s0Ti3RXd4601G8fAJ3zKlZmdEop59mK5BjAE8NOBmvP4uI7PYlJsDAE76mKghVxvN94qb-KwW4p0wix9RoC8TEtoE3EYCr428v-k4nTpMWXQcC_xkHVIfpoA6E","dp":"LGJtrCIxo2DlCSccu0ivH8YzUS9uUbsKyOgNEpV3IB3vqZToi_k8TkwN9XNXCMXkRYIGtRwkxvp9TWLtIEKMtQ","dq":"XhBVCRvFE_ccZ7rxzfu7LToeSNBPW07v68tM94pEV2MFfVBHdWJd-gHbIPGVwC55Th9vAh9dDmv0TvBVkiblkQ","e":"AQAB","kty":"RSA","n":"n5KqvPI1MPDhazTKXLYn4_we09e3iEccb7QJ8dRxApN1rpxTymRWabUafC56fArDF0lvIZ7fZl0LzX5Z_3mrqulebEPTFRrbdDwwcqa2KZ7Tctfh6MgUFm5xOAwRG33NlX3Ny1dP-Ek2irXJOHt9AecbEZFZKmpgrsrTyG6Ekfs","p":"1LoOk3MFiJpsjJCkMkaDb0TXXMxuZ5f9-iMVgR1ZoammzQziBj-72CrD21Rxmuuc6en8w4HtHLSOlPQtcOKzMw","q":"wAiSzr1NVdsYulhGYAa1ONZSKVxlFS7N_UAjPQgFf-xTYog2RbZfolheDv92mJp2qqFJdVMzQkbeMeTj9xqmGQ","qi":"eFqCOgR0wnpkjZGwh63pV8aNhh1-GfhYjqF2jSrh6rnsVHnhz3LRROSzUDarms7LjW3eHiygyHHSF2-ejTMMKQ"}`

		jwkMap := map[string]interface{}{}
		json.Unmarshal([]byte(jwkAsJSON), &jwkMap)

		jwk, err := MapToJwk(jwkMap)

		if assert.NoError(t, err) {
			assert.Equal(t, jwa.KeyType("RSA"), jwk.KeyType())
		}
	})

	t.Run("with missing data", func(t *testing.T) {
		jwkMap := map[string]interface{}{}
		_, err := MapToJwk(jwkMap)

		assert.Error(t, err)
	})
}

func TestPemToJwk(t *testing.T) {
	t.Run("generated jwk from pem", func(t *testing.T) {
		pub := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9wJQN59PYsvIsTrFuTqS\nLoUBgwdRfpJxOa5L8nOALxNk41MlAg7xnPbvnYrOHFucfWBTDOMTKBMSmD4WDkaF\ndVrXAML61z85Le8qsXfX6f7TbKMDm2u1O3cye+KdJe8zclK9sTFzSD0PP0wfw7wf\nlACe+PfwQgeOLPUWHaR6aDfaA64QEdfIzk/IL3S595ixaEn0huxMHgXFX35Vok+o\nQdbnclSTo6HUinkqsHUu/hGHApkE3UfT6GD6SaLiB9G4rAhlrDQ71ai872t4FfoK\n7skhe8sP2DstzAQRMf9FcetrNeTxNL7Zt4F/qKm80cchRZiFYPMCYyjQphyBCoJf\n0wIDAQAB\n-----END PUBLIC KEY-----"

		jwk, err := PemToJwk([]byte(pub))

		if assert.NoError(t, err) {
			assert.Equal(t, jwa.KeyType("RSA"), jwk.KeyType())
		}
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
