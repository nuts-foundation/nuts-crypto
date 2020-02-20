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
	"encoding/json"
	"encoding/pem"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/aescbc"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_serialNumberUniqueness(t *testing.T) {
	r := make(map[int64]bool, 0)
	for i := 0; i < 100000; i++ {
		serial, err := serialNumber()
		if !assert.NoError(t, err) {
			return
		}
		if r[serial] {
			assert.Failf(t, "duplicate found", "serial: %d", serial)
			return
		}
		r[serial] = true
	}
}

func TestCrypto_decryptWithSymmetricKey(t *testing.T) {
	t.Run("nonce empty", func(t *testing.T) {
		_, err := decryptWithSymmetricKey(make([]byte, 0), aescbc.AesCbcHmac{}, make([]byte, 0))
		assert.EqualErrorf(t, err, ErrIllegalNonce.Error(), "error")
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

func TestCrypto_PublicKeyToPem(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		result, err := PublicKeyToPem(&key.PublicKey)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, result)
		assert.Contains(t, result, "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, result, "-----END PUBLIC KEY-----")
		decoded, rest := pem.Decode([]byte(result))
		assert.Len(t, rest, 0)
		assert.NotNil(t, decoded)
	})
	t.Run("wrong public key gives error", func(t *testing.T) {
		_, err := PublicKeyToPem(&rsa.PublicKey{})
		assert.Error(t, err)
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
	t.Run("invalid PEM", func(t *testing.T) {
		_, err := PemToJwk([]byte("hello world"))
		assert.Error(t, err)
	})
}
