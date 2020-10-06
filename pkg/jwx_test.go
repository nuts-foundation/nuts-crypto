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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jws/sign"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-crypto/test"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestSignJWT(t *testing.T) {
	claims := map[string]interface{}{"iss": "nuts"}
	t.Run("creates valid JWT using rsa keys", func(t *testing.T) {
		key, _ := rsa2.GenerateKey(rand.Reader, 2048)
		tokenString, err := SignJWT(key, claims, nil)

		assert.Nil(t, err)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return key.Public(), nil
		})

		assert.True(t, token.Valid)
		assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
	})

	t.Run("creates valid JWT using ec keys", func(t *testing.T) {
		p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

		keys := []*ecdsa.PrivateKey{p256, p384, p521}

		for _, key := range keys {
			name := fmt.Sprintf("using %s", key.Params().Name)
			t.Run(name, func(t *testing.T) {
				tokenString, err := SignJWT(key, claims, nil)

				if assert.Nil(t, err) {
					token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
						return key.Public(), nil
					})

					if assert.Nil(t, err) {
						assert.True(t, token.Valid)
						assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
					}
				}
			})
		}
	})

	t.Run("sets correct headers", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		raw, _ := SignJWT(key, claims, map[string]interface{}{"x5c": []string{"BASE64"}})
		token, _ := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
			return key.Public(), nil
		})

		assert.Equal(t, "JWT", token.Header["typ"])
		assert.Equal(t, "ES256", token.Header["alg"])
		assert.Equal(t, []interface{}{"BASE64"}, token.Header["x5c"])
	})

	t.Run("returns error on unknown curve", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		_, err := SignJWT(key, claims, nil)

		assert.NotNil(t, err)
	})

	t.Run("returns error on unsupported crypto", func(t *testing.T) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		_, err := SignJWT(key, claims, nil)

		assert.NotNil(t, err)
	})
}

func TestCrypto_PublicKeyInJWK(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)

	t.Run("Public key is returned from storage", func(t *testing.T) {
		pub, err := client.GetPublicKeyAsJWK(key)

		assert.NoError(t, err)
		assert.NotNil(t, pub)
		assert.Equal(t, jwa.RSA, pub.KeyType())
	})

	t.Run("Public key for unknown entity returns error", func(t *testing.T) {
		_, err := client.GetPublicKeyAsJWK(key.WithQualifier("foo"))

		if assert.Error(t, err) {
			assert.True(t, errors.Is(err, storage.ErrNotFound))
		}
	})
}

func TestCrypto_SignJWT(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)

	t.Run("creates valid JWT", func(t *testing.T) {
		tokenString, err := client.SignJWT(map[string]interface{}{"iss": "nuts"}, key)

		assert.Nil(t, err)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			pubKey, _ := client.Storage.GetPublicKey(key)
			return pubKey, nil
		})

		assert.True(t, token.Valid)
		assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
	})

	t.Run("returns error for not found", func(t *testing.T) {
		_, err := client.SignJWT(map[string]interface{}{"iss": "nuts"}, key.WithQualifier("notfound"))

		assert.True(t, errors.Is(err, storage.ErrNotFound))
	})
}

func TestCrypto_SignJWTRFC003(t *testing.T) {
	client := createCrypto(t)
	c, _ := client.SelfSignVendorCACertificate("test")
	client.StoreVendorCACertificate(c)

	t.Run("creates valid JWT", func(t *testing.T) {
		tokenString, err := client.SignJWTRFC003(map[string]interface{}{"iss": "nuts"}, key)

		if !assert.NoError(t, err) {
			return
		}

		actual, err := jws.Parse(strings.NewReader(tokenString))
		if !assert.NoError(t, err) {
			return
		}
		chain, err := cert.GetX509ChainFromHeaders(actual.Signatures()[0].ProtectedHeaders())
		assert.Equal(t, "test oauth", chain[0].Subject.CommonName)
	})

	t.Run("Returns error on missing CA", func(t *testing.T) {
		client := createCrypto(t)
		_, err := client.SignJWTRFC003(map[string]interface{}{"iss": "nuts"}, key)

		assert.Error(t, err)
	})
}

func TestCrypto_SignJWS(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	key := types.KeyForEntity(types.LegalEntity{URI: t.Name()})
	privateKey := test.GenerateRSAKey()
	_ = client.Storage.SavePrivateKey(key, privateKey)
	t.Run("ok", func(t *testing.T) {
		certAsASN1 := test.GenerateCertificateEx(time.Now(), privateKey, 1, false, x509.KeyUsageContentCommitment)
		_ = client.Storage.SaveCertificate(key, certAsASN1)
		dataToBeSigned := []byte("Hello, World!")
		jwsAsBytes, err := client.SignJWS(dataToBeSigned, key)
		if !assert.NoError(t, err) {
			return
		}
		// Validate signature
		payload, err := client.VerifyJWS(jwsAsBytes, time.Now(), client.trustStore)
		assert.NoError(t, err)
		assert.Equal(t, dataToBeSigned, payload)
	})
	t.Run("error - key/certificate missing", func(t *testing.T) {
		jwsAsBytes, err := client.SignJWS([]byte{}, key.WithQualifier("non-existent"))
		assert.EqualError(t, err, "signing certificate and/or private not present: [TestCrypto_SignJWS|non-existent]")
		assert.Nil(t, jwsAsBytes)
	})
	t.Run("error - non signing certificate", func(t *testing.T) {
		certAsASN1 := test.GenerateCertificateEx(time.Now(), privateKey, 1, false, x509.KeyUsageCRLSign)
		_ = client.Storage.SaveCertificate(key, certAsASN1)
		dataToBeSigned := []byte("Hello, World!")
		jwsAsBytes, err := client.SignJWS(dataToBeSigned, key)
		assert.EqualError(t, err, "certificate is not meant for signing (keyUsage = digitalSignature | contentCommitment)")
		assert.Nil(t, jwsAsBytes)
	})
}

// Tests both SignJWSEphemeral and VerifyJWS functions
func TestCrypto_SignJWSEphemeralAndVerify(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	selfSignCertificate := func(key types.KeyIdentifier, keyUsage x509.KeyUsage) *x509.Certificate {
		client.GenerateKeyPair(key, false)
		privateKey, _ := client.GetPrivateKey(key)
		csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:   pkix.Name{CommonName: key.Owner()},
			PublicKey: privateKey.Public(),
		}, privateKey)
		asn1Cert, _ := client.SignCertificate(key, key, csr, CertificateProfile{NumDaysValid: 10, IsCA: true, KeyUsage: keyUsage})
		cert, _ := x509.ParseCertificate(asn1Cert)
		return cert
	}

	verifier := poolCertVerifier{pool: x509.NewCertPool()}
	caCertificate := selfSignCertificate(key, 0)
	verifier.pool.AddCert(caCertificate)

	var sourceStruct = struct {
		Field1 string
		Field2 string
	}{
		Field1: "Hello",
		Field2: "World",
	}
	dataToBeSigned, _ := json.Marshal(sourceStruct)

	t.Run("ok - roundtrip", func(t *testing.T) {
		signature, err := client.SignJWSEphemeral(dataToBeSigned, key, x509.CertificateRequest{
			Subject: pkix.Name{CommonName: key.Owner()},
		}, time.Now())
		if !assert.NoError(t, err) {
			return
		}
		payload, err := client.VerifyJWS(signature, time.Now(), verifier)
		if !assert.NoError(t, err) {
			return
		}
		// Verify actual contents of JWS
		assert.Equal(t, payload, dataToBeSigned)
		parsedSignature, err := jws.Parse(bytes.NewReader(signature))
		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, parsedSignature.Signatures(), 1) {
			return
		}
		parsedHeaders := parsedSignature.Signatures()[0].ProtectedHeaders()
		assert.Equal(t, "RS256", parsedHeaders.Algorithm().String())
		assert.Equal(t, dataToBeSigned, parsedSignature.Payload())
	})
	t.Run("error - certificate not trusted", func(t *testing.T) {
		signature, _ := client.SignJWSEphemeral(dataToBeSigned, key, x509.CertificateRequest{
			Subject: pkix.Name{CommonName: key.Owner()},
		}, time.Now())
		payload, err := client.VerifyJWS(signature, time.Now(), poolCertVerifier{pool: x509.NewCertPool()})
		assert.EqualError(t, err, "X.509 certificate not trusted: x509: certificate signed by unknown authority")
		assert.Nil(t, payload)
	})
	t.Run("error - certificate not valid at time of signing", func(t *testing.T) {
		signature, err := client.SignJWSEphemeral(dataToBeSigned, key, x509.CertificateRequest{
			Subject: pkix.Name{CommonName: key.Owner()},
		}, time.Now())
		if !assert.NoError(t, err) {
			return
		}
		payload, err := client.VerifyJWS(signature, time.Now().AddDate(-1, 0, 0), verifier)
		assert.Contains(t, err.Error(), "x509: certificate has expired or is not yet valid")
		assert.Nil(t, payload)
	})
	t.Run("error - certificate not meant for signing", func(t *testing.T) {
		privateKey := test.GenerateRSAKey()
		h := jws.StandardHeaders{}
		certificate := selfSignCertificate(key, 0)
		verifier.pool.AddCert(certificate)
		h.Set(jws.X509CertChainKey, cert.MarshalX509CertChain([]*x509.Certificate{certificate}))
		sig, _ := jws.Sign(dataToBeSigned, jwsAlgorithm, privateKey, jws.WithHeaders(&h))
		payload, err := client.VerifyJWS(sig, time.Now(), verifier)
		assert.EqualError(t, err, "certificate is not meant for signing (keyUsage = digitalSignature | contentCommitment)")
		assert.Nil(t, payload)
	})
	t.Run("error - signature invalid (cert doesn't match signing key)", func(t *testing.T) {
		privateKey := test.GenerateRSAKey()
		h := jws.StandardHeaders{}
		certificate := selfSignCertificate(key, x509.KeyUsageDigitalSignature)
		verifier.pool.AddCert(certificate)
		h.Set(jws.X509CertChainKey, cert.MarshalX509CertChain([]*x509.Certificate{certificate}))
		sig, _ := jws.Sign(dataToBeSigned, jwsAlgorithm, privateKey, jws.WithHeaders(&h))
		payload, err := client.VerifyJWS(sig, time.Now(), verifier)
		assert.EqualError(t, err, "failed to verify message: crypto/rsa: verification error")
		assert.Nil(t, payload)
	})
	t.Run("error - invalid JWS format", func(t *testing.T) {
		payload, err := client.VerifyJWS([]byte{1, 2, 3, 4}, time.Now(), poolCertVerifier{})
		assert.Contains(t, err.Error(), "unable to parse signature")
		assert.Nil(t, payload)
	})
	t.Run("error - multiple signatures", func(t *testing.T) {
		signer, _ := sign.New(jwa.HS256)
		sharedKey := []byte("foobar")
		sig, _ := jws.SignMulti(dataToBeSigned, jws.WithSigner(signer, sharedKey, nil, nil), jws.WithSigner(signer, sharedKey, nil, nil))
		payload, err := client.VerifyJWS(sig, time.Now(), poolCertVerifier{})
		assert.Contains(t, err.Error(), "JWS contains more than 1 signature")
		assert.Nil(t, payload)
	})
	t.Run("error - incorrect signing algorithm", func(t *testing.T) {
		sig, _ := jws.Sign(dataToBeSigned, jwa.HS256, []byte("foobar"))
		payload, err := client.VerifyJWS(sig, time.Now(), poolCertVerifier{})
		assert.Contains(t, err.Error(), "JWS is signed with incorrect algorithm (expected = RS256, actual = HS256)")
		assert.Nil(t, payload)
	})
	t.Run("error - key strength insufficient", func(t *testing.T) {
		// Switch to strict mode just for this test
		os.Setenv("NUTS_STRICTMODE", "true")
		core.NutsConfig().Load(&cobra.Command{})
		defer core.NutsConfig().Load(&cobra.Command{})
		defer os.Unsetenv("NUTS_STRICTMODE")
		key := test.GenerateRSAKey()
		certBytes := test.GenerateCertificate(time.Now(), 2, key)
		certificate, _ := x509.ParseCertificate(certBytes)
		headers := jws.StandardHeaders{
			JWSx509CertChain: cert.MarshalX509CertChain([]*x509.Certificate{certificate}),
		}
		sig, _ := jws.Sign(dataToBeSigned, jwa.RS256, key, jws.WithHeaders(&headers))
		pool := x509.NewCertPool()
		pool.AddCert(certificate)
		payload, err := client.VerifyJWS(sig, time.Now(), poolCertVerifier{})
		assert.EqualError(t, err, ErrInvalidKeySize.Error())
		assert.Nil(t, payload)
	})
	t.Run("error - no X.509 chain", func(t *testing.T) {
		key := test.GenerateRSAKey()
		sig, _ := jws.Sign(dataToBeSigned, jwsAlgorithm, key)
		payload, err := client.VerifyJWS(sig, time.Now(), poolCertVerifier{})
		assert.Contains(t, err.Error(), "JWK doesn't contain X509 chain header (x5c) header")
		assert.Nil(t, payload)
	})
	t.Run("error - invalid X.509 chain", func(t *testing.T) {
		key := test.GenerateRSAKey()
		h := jws.StandardHeaders{}
		h.JWSx509CertChain = []string{"invalid-cert"}
		sig, _ := jws.Sign(dataToBeSigned, jwsAlgorithm, key, jws.WithHeaders(&h))
		payload, err := client.VerifyJWS(sig, time.Now(), poolCertVerifier{})
		assert.Contains(t, err.Error(), ErrInvalidCertChain.Error())
		assert.Nil(t, payload)
	})
}

func TestCrypto_VerifyWith(t *testing.T) {
	createCrypto(t)

	t.Run("A signed piece of data can be verified", func(t *testing.T) {
		data := []byte("hello")
		client := createCrypto(t)
		createCrypto(t)

		client.GenerateKeyPair(key, false)

		sig, err := client.Sign(data, key)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		pub, err := client.GetPublicKeyAsJWK(key)

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
	t.Run("error - signature invalid", func(t *testing.T) {
		client := createCrypto(t)
		createCrypto(t)

		client.GenerateKeyPair(key, false)
		keyAsJWK, _ := client.GetPublicKeyAsJWK(key)
		result, err := client.VerifyWith([]byte("hello"), []byte{1, 2, 3}, keyAsJWK)
		assert.False(t, result)
		assert.EqualError(t, err, "crypto/rsa: verification error")
	})
}
