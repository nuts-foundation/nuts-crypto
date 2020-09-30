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

package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-crypto/test"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/stretchr/testify/assert"
)

func TestCrypto_PublicKeyToPem(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		key := test.GenerateRSAKey()
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

func TestCertificateToJWK(t *testing.T) {
	t.Run("Convert X.509 certificate to JWK", func(t *testing.T) {
		certBase64 := "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		key, err := CertificateToJWK(cert)
		if !assert.NoError(t, err) {
			return
		}
		chainInterf, ok := key.Get(jwk.X509CertChainKey)
		if !assert.True(t, ok) {
			return
		}
		chain := chainInterf.([]*x509.Certificate)
		assert.Len(t, chain, 1)
		assert.Equal(t, cert, chain[0])
	})
}

func TestJwkToMap(t *testing.T) {
	t.Run("Generates map for RSA key", func(t *testing.T) {
		rsa := test.GenerateRSAKey()
		jwk, _ := jwk.New(rsa)

		jwkMap, err := JwkToMap(jwk)

		if assert.NoError(t, err) {
			assert.Equal(t, jwa.KeyType("RSA"), jwkMap["kty"])
		}
	})
	t.Run("Generates map for X.509 certificate", func(t *testing.T) {
		certBase64 := "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		key, _ := CertificateToJWK(cert)

		jwkMap, err := JwkToMap(key)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, jwkMap["x5c"], 1) {
			return
		}
		assert.Equal(t, certBase64, jwkMap["x5c"].([]string)[0])
	})
}

func TestMapToJwk(t *testing.T) {
	t.Run("Generates Jwk from map", func(t *testing.T) {
		jwkAsJSON := `{"d":"Ce3obeVsZeU3QaKBTQ-Qn-EaUfhEVViHbnP3gnLDrXNbiUf09s0Ti3RXd4601G8fAJ3zKlZmdEop59mK5BjAE8NOBmvP4uI7PYlJsDAE76mKghVxvN94qb-KwW4p0wix9RoC8TEtoE3EYCr428v-k4nTpMWXQcC_xkHVIfpoA6E","dp":"LGJtrCIxo2DlCSccu0ivH8YzUS9uUbsKyOgNEpV3IB3vqZToi_k8TkwN9XNXCMXkRYIGtRwkxvp9TWLtIEKMtQ","dq":"XhBVCRvFE_ccZ7rxzfu7LToeSNBPW07v68tM94pEV2MFfVBHdWJd-gHbIPGVwC55Th9vAh9dDmv0TvBVkiblkQ","e":"AQAB","kty":"RSA","n":"n5KqvPI1MPDhazTKXLYn4_we09e3iEccb7QJ8dRxApN1rpxTymRWabUafC56fArDF0lvIZ7fZl0LzX5Z_3mrqulebEPTFRrbdDwwcqa2KZ7Tctfh6MgUFm5xOAwRG33NlX3Ny1dP-Ek2irXJOHt9AecbEZFZKmpgrsrTyG6Ekfs","p":"1LoOk3MFiJpsjJCkMkaDb0TXXMxuZ5f9-iMVgR1ZoammzQziBj-72CrD21Rxmuuc6en8w4HtHLSOlPQtcOKzMw","q":"wAiSzr1NVdsYulhGYAa1ONZSKVxlFS7N_UAjPQgFf-xTYog2RbZfolheDv92mJp2qqFJdVMzQkbeMeTj9xqmGQ","qi":"eFqCOgR0wnpkjZGwh63pV8aNhh1-GfhYjqF2jSrh6rnsVHnhz3LRROSzUDarms7LjW3eHiygyHHSF2-ejTMMKQ"}`

		jwkMap := map[string]interface{}{}
		json.Unmarshal([]byte(jwkAsJSON), &jwkMap)

		jwk, err := MapToJwk(jwkMap)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, jwa.KeyType("RSA"), jwk.KeyType())
		assert.NotNil(t, jwkMap["d"], "function altered input map")
	})

	t.Run("with missing data", func(t *testing.T) {
		jwkMap := map[string]interface{}{}
		_, err := MapToJwk(jwkMap)

		assert.Error(t, err)
	})
}

func TestMapsToJwkSet(t *testing.T) {
	t.Run("Generates set from maps", func(t *testing.T) {
		jwkAsJSON := `{"d":"Ce3obeVsZeU3QaKBTQ-Qn-EaUfhEVViHbnP3gnLDrXNbiUf09s0Ti3RXd4601G8fAJ3zKlZmdEop59mK5BjAE8NOBmvP4uI7PYlJsDAE76mKghVxvN94qb-KwW4p0wix9RoC8TEtoE3EYCr428v-k4nTpMWXQcC_xkHVIfpoA6E","dp":"LGJtrCIxo2DlCSccu0ivH8YzUS9uUbsKyOgNEpV3IB3vqZToi_k8TkwN9XNXCMXkRYIGtRwkxvp9TWLtIEKMtQ","dq":"XhBVCRvFE_ccZ7rxzfu7LToeSNBPW07v68tM94pEV2MFfVBHdWJd-gHbIPGVwC55Th9vAh9dDmv0TvBVkiblkQ","e":"AQAB","kty":"RSA","n":"n5KqvPI1MPDhazTKXLYn4_we09e3iEccb7QJ8dRxApN1rpxTymRWabUafC56fArDF0lvIZ7fZl0LzX5Z_3mrqulebEPTFRrbdDwwcqa2KZ7Tctfh6MgUFm5xOAwRG33NlX3Ny1dP-Ek2irXJOHt9AecbEZFZKmpgrsrTyG6Ekfs","p":"1LoOk3MFiJpsjJCkMkaDb0TXXMxuZ5f9-iMVgR1ZoammzQziBj-72CrD21Rxmuuc6en8w4HtHLSOlPQtcOKzMw","q":"wAiSzr1NVdsYulhGYAa1ONZSKVxlFS7N_UAjPQgFf-xTYog2RbZfolheDv92mJp2qqFJdVMzQkbeMeTj9xqmGQ","qi":"eFqCOgR0wnpkjZGwh63pV8aNhh1-GfhYjqF2jSrh6rnsVHnhz3LRROSzUDarms7LjW3eHiygyHHSF2-ejTMMKQ"}`

		jwkMap := map[string]interface{}{}
		json.Unmarshal([]byte(jwkAsJSON), &jwkMap)

		set, err := MapsToJwkSet([]map[string]interface{}{jwkMap})

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, set.Keys, 1)
		assert.NotNil(t, jwkMap["d"], "function altered input map")
	})

	t.Run("with missing data", func(t *testing.T) {
		jwkMap := map[string]interface{}{}
		_, err := MapsToJwkSet([]map[string]interface{}{jwkMap})

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

func TestMapToX509CertChain(t *testing.T) {
	t.Run("jwk", func(t *testing.T) {
		jwkAsJSON := `{
  "e": "AQAB",
  "kty": "RSA",
  "n": "n5KqvPI1MPDhazTKXLYn4_we09e3iEccb7QJ8dRxApN1rpxTymRWabUafC56fArDF0lvIZ7fZl0LzX5Z_3mrqulebEPTFRrbdDwwcqa2KZ7Tctfh6MgUFm5xOAwRG33NlX3Ny1dP-Ek2irXJOHt9AecbEZFZKmpgrsrTyG6Ekfs",
  "x5c": "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
}`
		key := map[string]interface{}{}
		json.Unmarshal([]byte(jwkAsJSON), &key)
		chain, err := MapToX509CertChain(key)
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, chain, 1)
	})
	t.Run("jws", func(t *testing.T) {
		jwsAsJSON := "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlESmpDQ0FnNmdBd0lCQWdJSUJWekVLMXI4WXlrd0RRWUpLb1pJaHZjTkFRRUxCUUF3VVRFTE1Ba0dBMVVFQmhNQ1Rrd3hHREFXQmdOVkJBb1REMFp2YjJKaGNpQlRiMlowZDJGeVpURW9NQ1lHQTFVRUF4TWZSbTl2WW1GeUlGTnZablIzWVhKbElFTkJJRWx1ZEdWeWJXVmthV0YwWlRBZUZ3MHlNREF6TURreE16UXlOREJhRncweU1EQXpNRGt4TXpRek5EQmFNRUV4Q3pBSkJnTlZCQVlUQWs1TU1SZ3dGZ1lEVlFRS0V3OUdiMjlpWVhJZ1UyOW1kSGRoY21VeEdEQVdCZ05WQkFNVEQwWnZiMkpoY2lCVGIyWjBkMkZ5WlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTW83M0FDd3Z2azlCZnQrRXh5OUFZRmNLeHBjU29MZnR1KzBsaVV1WjJwSFIvcTM1ZmRzT0o0bys5QWRoeWU0bGxsUlRwcGowY2xjTnkyUTM4UkxkV2dBT0dPYXpCN0RRN3Jqa2hDQ00rSlBLUHgwQnFzTDhSekVidnVtRzFrdFFmWTM2SGdQd0N2MGV6VzVDUG1CN1ViMTB3STkzMTBlajV5eG1kSUI5S2ZJeitqR2JLL2JheDVQYjdia3AzcFA1RnhKNG5jbkoxYmdHS3F0SWUvUDE1K2JyaWJHcU0zWWcrTHhqWlhEZkZMZDhEbWdPcjBRd3AyRmpodXhtb2twUmdGSW5vL2hidHlEQkQvM1ZZb1kvcXVVelVWUDJKcnhDejVmSkl1WUxlUWFEMVJ2TXAra0xTOFMrOFNqSlgweXMrRXI5R3haalljRnRLQVlWQVhkZG1jQ0F3RUFBYU1TTUJBd0RnWURWUjBQQVFIL0JBUURBZ2VBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFBd0ljcXJNdUZrbUVLWGZOaVdWVWJGNW1maHBHaFlrR21NWWUvYjNOWHU4WFVrY1EvdEp2N1NsTnJ5ZHRrT3VwTGNhN2VaQVdBZk5XTHUrWGgxTENnbVhJWXNWcksrNm5IRlk4eE5LeE5iMmNocHpDZ1NYcmhLY3RGMTFscXFlSW9kOHdXR0tIa2o5SFp0c0lwR3ltUmdsZ2hOMDk5ZldEVEVHNlBWRlBoYWhmZnFiTi8zODhucTloTnl6aXEzOHIzaFpwVlZzOWZuWWoyaFZKSjVtZktrNFBZVUFVODdOVmxhOTV4ditiaVNvTkRUOXR5WDVXLzRKMGc2b3lhZjlaYlcxMzRCd2xwWEFRcVRqUXIzS2cvS3NGZzRicXFNQ2U0SnBtNjBmS3JtMDhXWDUxZldZdU04bGxDVjcrVzZkYXRRaWRZYmFPRFExaUJFbCtTQUpWK2ciXX0.eyJpZGVudGlmaWVyIjoiZm9vYmFyIiwibmFtZSI6IkZvb2JhciBTb2Z0d2FyZSIsImRvbWFpbiI6ImhlYWx0aGNhcmUiLCJrZXlzIjpbeyJjdCI6InZlbmRvci1jYSIsImUiOiJBUUFCIiwia3R5IjoiUlNBIiwibiI6InhiNDdXazlMRWFMNXFaWWUydmdGN0RfZ3dONGluT212VVdDaVI3bm1aUm9yMk9TQUYyVGVjbWJUTlJKak56a2ZLc0pOanhvakM5Z0tBeHFsT3F2eEtseFNVZTh0QklhalNDSmI3S1pGYW1ESTA5XzR3RGp1S0pLU1BzN2pCMFFlZ1R2bXpiTzhETkxpSmNJQVZ6Z1BuaHRhM2lRWnFYNkVUNnA4RUhYVlhzSV81NE9XWU1pMDJyT3VlYkFRYVBPdzQxOXJ6ZmZ0V3NkTlVQNlBNMEMxRlJPTkdXVFJnZXlqaHBqOXctY3pVd1NuUm1UVmdIRU9PMEFaTjVlbTZCTzZITDBxWWszb1RCN2MwbWkwdXZpSEdiTUxnTFotTTRYTmFVWmRXXzdJVnpDdXZ3MWFudm1lUEdTZUhYUlpUNFBBVnlBWkZKTjdnSUZaQ01rUEJndEhBdyIsIng1YyI6Ik1JSURoRENDQW15Z0F3SUJBZ0lJUFd0Z3pNVlNRQ2t3RFFZSktvWklodmNOQVFFTEJRQXdVVEVMTUFrR0ExVUVCaE1DVGt3eEdEQVdCZ05WQkFvVEQwWnZiMkpoY2lCVGIyWjBkMkZ5WlRFb01DWUdBMVVFQXhNZlJtOXZZbUZ5SUZOdlpuUjNZWEpsSUVOQklFbHVkR1Z5YldWa2FXRjBaVEFlRncweU1EQXpNRGt4TXpReU5EQmFGdzB5TVRBek1Ea3hNelF5TkRCYU1GRXhDekFKQmdOVkJBWVRBazVNTVJnd0ZnWURWUVFLRXc5R2IyOWlZWElnVTI5bWRIZGhjbVV4S0RBbUJnTlZCQU1USDBadmIySmhjaUJUYjJaMGQyRnlaU0JEUVNCSmJuUmxjbTFsWkdsaGRHVXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFERnZqdGFUMHNSb3ZtcGxoN2ErQVhzUCtEQTNpS2M2YTlSWUtKSHVlWmxHaXZZNUlBWFpONXladE0xRW1NM09SOHF3azJQR2lNTDJBb0RHcVU2cS9FcVhGSlI3eTBFaHFOSUlsdnNwa1ZxWU1qVDMvakFPTzRva3BJK3p1TUhSQjZCTytiTnM3d00wdUlsd2dCWE9BK2VHMXJlSkJtcGZvUlBxbndRZGRWZXdqL25nNVpneUxUYXM2NTVzQkJvODdEalgydk45KzFheDAxUS9vOHpRTFVWRTQwWlpOR0I3S09HbVAzRDV6TlRCS2RHWk5XQWNRNDdRQmszbDZib0U3b2N2U3BpVGVoTUh0elNhTFM2K0ljWnN3dUF0bjR6aGMxcFJsMWIvc2hYTUs2L0RWcWUrWjQ4Wko0ZGRGbFBnOEJYSUJrVWszdUFnVmtJeVE4R0MwY0RBZ01CQUFHallEQmVNQTRHQTFVZER3RUIvd1FFQXdJQmhqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01DQUdBMVVkRVFRWk1CZWdGUVlKS3dZQkJBR0RyRU1Fb0FnTUJtWnZiMkpoY2pBWkJna3JCZ0VFQVlPc1F3TUVEQXdLYUdWaGJIUm9ZMkZ5WlRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQWdRakxtWkVuUkNqTy82UnIxVm5tdExaU3BoM0pKSjNOd0JHdmhrT0huZHZZRWJRejZjdG8yWjBPZEJyeFBKN01XNXhjQk5xa1l6OUU2T29mNEhVYmxScFBzazF6SFRmdzF5V1NzMUwyck1icTdJNXdzVXNRYWszVXdhU1NxOGZFZnJKNVltT2NhbExNU2ZsQS94S3p3c3kxbVZ0dEpndFJ1RWpacy9KZ29BREpnaDRFbEpXWDB1bHRYRGwxNHNRM05XbjNYa1l5cUsyQ1NjSDVVbjZBeFNWYTN6ZktOdUxXWCtBY3VXRVo1OW5sN3NQMzNhT1lYZ09QcmpDSzFGS29LN2Z2MjN2QXNwLzJvT0daUncyNEpTZFJLWFM0NzBSSVhacElkTCswbzcyTitSQUtzS25MdUZMTVJSN043aEE3UHhKRkNZL2s3YTZkMkEyVTVmYmxUZz09In1dfQ.BbpcIZcR7nl6RYqBEo9vicceQZZpLAZuUlGcc0tc2McdYGj9KCOuJ8lfEgBNjDzd9JqiNG-sO54762fbOOJ5Y70KcX8PXF8IlBjq1Z1mqmFli1WzCJ9PVbitiCAilTdBDBAhtfR77omAMRmoSUioxJQ5rRW1Su_fEumlARsmL4D4j8-v8Ke7QafW-ZVRc91aoNQIQkuuy1tcATUT7Yn-VMiX3cxIsS2y7pmpftEZWcv4WbPkg6vveigCGJHiP9bFc-m70VD3oMAJu6v9nHBfqm2gVh99MN2yKg-vd5B_bG0wmNHKwv9d_7ouljWGExFB3C33Ir5zRRvRRUToyWuLIw"
		actual, _ := jws.Parse(strings.NewReader(jwsAsJSON))
		chain, err := GetX509ChainFromHeaders(actual.Signatures()[0].ProtectedHeaders())
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, chain, 1)
	})
}

func TestValidateCertificate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		rsaKey := test.GenerateRSAKey()
		asn1 := test.GenerateCertificate(time.Now().AddDate(0, 0, -1), 2, rsaKey)
		certificate, _ := x509.ParseCertificate(asn1)
		assert.NoError(t, ValidateCertificate(certificate, ValidAt(time.Now())))
		assert.Error(t, ValidateCertificate(certificate, ValidAt(time.Now().AddDate(1, 0, 0))))
	})
	t.Run("error - certificate is nil", func(t *testing.T) {
		assert.Error(t, ValidateCertificate(nil))
	})
}

func TestCopySANs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		rsaKey := test.GenerateRSAKey()
		asn1 := test.GenerateCertificate(time.Now().AddDate(0, 0, -1), 2, rsaKey)
		certificate, _ := x509.ParseCertificate(asn1)
		sans := CopySANs(certificate)
		assert.Len(t, sans, 1)
	})
}

func TestMarshalX509CertChain(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		certBase64 := "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		chain := MarshalX509CertChain([]*x509.Certificate{cert})
		assert.Len(t, chain, 1)
	})
}

func Test_deepCopyMap(t *testing.T) {
	expected := map[string]interface{}{}
	expected["flat"] = "foobar"
	expected["nested"] = map[string]interface{}{
		"nested": map[string]interface{}{
			"nested": map[string]interface{}{
				"value": "ok",
			},
		},
	}

	actual := deepCopyMap(expected)
	assert.True(t, reflect.DeepEqual(actual, expected))
	// Assert it's actually a copy
	delete(expected, "flat")
	assert.False(t, reflect.DeepEqual(actual, expected))
}

func TestValidateJWK(t *testing.T) {
	jwkAsJSON := `{
  "e": "AQAB",
  "kty": "RSA",
  "n": "n5KqvPI1MPDhazTKXLYn4_we09e3iEccb7QJ8dRxApN1rpxTymRWabUafC56fArDF0lvIZ7fZl0LzX5Z_3mrqulebEPTFRrbdDwwcqa2KZ7Tctfh6MgUFm5xOAwRG33NlX3Ny1dP-Ek2irXJOHt9AecbEZFZKmpgrsrTyG6Ekfs",
  "x5c": "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
}`
	key := map[string]interface{}{}
	json.Unmarshal([]byte(jwkAsJSON), &key)
	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, ValidateJWK(key, key))
	})
	t.Run("error - invalid Go type", func(t *testing.T) {
		invalidMap := map[bool]interface{}{}
		assert.Error(t, ValidateJWK(key, invalidMap))
	})
	t.Run("error - invalid JWK", func(t *testing.T) {
		invalidMap := map[string]interface{}{
			"kty": "foobar",
		}
		assert.Error(t, ValidateJWK(key, invalidMap))
	})
}

func TestCertificateToPEM(t *testing.T) {
	rsaKey := test.GenerateRSAKey()
	asn1 := test.GenerateCertificate(time.Now().AddDate(0, 0, -1), 2, rsaKey)
	certificate, _ := x509.ParseCertificate(asn1)
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: asn1,
	})

	t.Run("ok", func(t *testing.T) {
		assert.Equal(t, string(pemEncoded), CertificateToPEM(certificate))
	})
}

func TestPemToX509(t *testing.T) {
	rsaKey := test.GenerateRSAKey()
	asn1 := test.GenerateCertificate(time.Now().AddDate(0, 0, -1), 2, rsaKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: asn1,
	})

	t.Run("decodes PEM to x509.Certificate", func(t *testing.T) {
		cert, err := PemToX509(pemEncoded)
		if assert.NoError(t, err) {
			assert.Equal(t, "Unit Test", cert.Subject.CommonName)
		}
	})

	t.Run("incorrect data gives error", func(t *testing.T) {
		_, err := PemToX509([]byte{})
		if assert.Error(t, err) {
			assert.Equal(t, "failed to decode PEM block containing certificate", err.Error())
		}
	})

	t.Run("too much data gives error", func(t *testing.T) {
		var pemCopy []byte
		copy(pemEncoded, pemCopy)
		pemCopy = append(pemCopy, 0x65)

		_, err := PemToX509(pemCopy)
		if assert.Error(t, err) {
			assert.True(t, strings.Contains(err.Error(), ErrInvalidCertificate.Error()))
		}
	})
}

func TestValidBetween(t *testing.T) {
	t.Run("not valid", func(t *testing.T) {
		certBase64 := "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		err := ValidBetween(time.Now().AddDate(30, 0, 0), time.Now().AddDate(32, 0, 0))(cert)
		assert.Error(t, err)
	})
	t.Run("valid", func(t *testing.T) {
		certBase64 := "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		start := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
		end := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		err := ValidBetween(start, end)(cert)
		assert.NoError(t, err)
	})
}

func TestAtMoment(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		certBase64 := "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		err := ValidAt(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))(cert)
		assert.NoError(t, err)
	})
	t.Run("not valid", func(t *testing.T) {
		certBase64 := "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		err := ValidAt(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))(cert)
		assert.Error(t, err)
	})
}

func TestIsCA(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		certBase64 := "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWVU+4="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		err := IsCA()(cert)
		assert.NoError(t, err)
	})
	t.Run("not valid", func(t *testing.T) {
		certBase64 := "MIIB1zCCAUCgAwIBAgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlVbml0IFRlc3QwHhcNMjAwNzI0MDc1MzU3WhcNMjAwODAzMDc1MzU3WjAUMRIwEAYDVQQDEwlVbml0IFRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK86zu1ycIhzFXLD8d/aDIP90yuioR4zq6+aqeBPmcxY7XAshJbclL3y/Ot6+LNgqE9tti5qJoqseFdLiUpHj4IVFKXOn6Ns0cuIPo95Y22j3yxAnumbsjM7jHhtUX7hf0Tx4x8H3mk0RjjE2UvW3LuAZs0pTVOl1mPD6njUDochAgMBAAGjOTA3MA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMBcGA1UdEQQQMA6BDHRlc3RAdGVzdC5ubDANBgkqhkiG9w0BAQsFAAOBgQB0i7klDjSW/QYwfFHMa+nkabTYVnxBDLeg87XhCVYa5RULxheOJ8vqFW62mDwOshhxacOkzcCWJ11Fo8CBEeTQjS3S8CLY27b9D3Io5l6+2p/bP0f88aSIRUYvPMpOvUPwpSRhZ9+/+oSWaXqm1L4Pi6ja0orjqiN9kFXxF9SvIA=="
		certASN1, _ := base64.StdEncoding.DecodeString(certBase64)
		cert, _ := x509.ParseCertificate(certASN1)
		err := IsCA()(cert)
		assert.Error(t, err)
	})
}

func TestMeantForSigning(t *testing.T) {
	privateKey := test.GenerateRSAKey()
	t.Run("invalid", func(t *testing.T) {
		certAsASN1 := test.GenerateCertificateEx(time.Now(), privateKey, 1, false, x509.KeyUsageCertSign)
		certificate, _ := x509.ParseCertificate(certAsASN1)
		err := MeantForSigning()(certificate)
		assert.EqualError(t, err, "certificate is not meant for signing (keyUsage = digitalSignature | contentCommitment)")
	})
	t.Run("valid (keyUsage = contentCommitment)", func(t *testing.T) {
		certAsASN1 := test.GenerateCertificateEx(time.Now(), privateKey, 1, false, x509.KeyUsageContentCommitment|x509.KeyUsageKeyAgreement)
		certificate, _ := x509.ParseCertificate(certAsASN1)
		err := MeantForSigning()(certificate)
		assert.NoError(t, err)
	})
	t.Run("valid (keyUsage = digitalSignature)", func(t *testing.T) {
		certAsASN1 := test.GenerateCertificateEx(time.Now(), privateKey, 1, false, x509.KeyUsageDigitalSignature|x509.KeyUsageCRLSign)
		certificate, _ := x509.ParseCertificate(certAsASN1)
		err := MeantForSigning()(certificate)
		assert.NoError(t, err)
	})
}

func TestPemToSigner(t *testing.T) {
	t.Run("Convert ED25519 key", func(t *testing.T) {
		pem, _ := ioutil.ReadFile("../../test/ed25519.sk")
		signer, err := PemToSigner(pem)
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("Convert EC key", func(t *testing.T) {
		pem, _ := ioutil.ReadFile("../../test/ec.sk")
		signer, err := PemToSigner(pem)
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("Convert RSA key", func(t *testing.T) {
		pem, _ := ioutil.ReadFile("../../test/rsa.sk")
		signer, err := PemToSigner(pem)
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("Convert PKIX key", func(t *testing.T) {
		pem, _ := ioutil.ReadFile("../../test/sk.pem")
		signer, err := PemToSigner(pem)
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("Convert garbage", func(t *testing.T) {
		_, err := PemToSigner([]byte{})
		if assert.Error(t, err) {
			assert.Equal(t, ErrWrongPrivateKey, err)
		}
	})
}
