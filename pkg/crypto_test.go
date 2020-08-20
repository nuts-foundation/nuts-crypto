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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-crypto/test"
	"github.com/nuts-foundation/nuts-go-test/io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/spf13/cobra"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe/aescbc"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jws/sign"
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

func TestCrypto_DecryptCipherTextFor(t *testing.T) {
	createCrypto(t)

	client := createCrypto(t)
	client.Config.Keysize = MinKeySize // required for RSA OAEP encryption

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
	client.Config.Keysize = MinKeySize // required for RSA OAEP encryption
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

func TestCrypto_SignFor(t *testing.T) {
	createCrypto(t)

	t.Run("error - private key does not exist", func(t *testing.T) {
		client := createCrypto(t)
		sig, err := client.Sign([]byte{1, 2, 3}, key)
		assert.Error(t, err)
		assert.Nil(t, sig)
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

func TestCrypto_SignJwtFor(t *testing.T) {
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

type poolCertVerifier struct {
	pool *x509.CertPool
}

func (n poolCertVerifier) Pool() *x509.CertPool {
	return n.pool
}

func (n * poolCertVerifier) AddCertificate(certificate *x509.Certificate) error {
	n.pool.AddCert(certificate)
	return nil
}

func (n poolCertVerifier) GetRoots(t time.Time) []*x509.Certificate {
	panic("implement me")
}

func (n poolCertVerifier) GetCertificates(i [][]*x509.Certificate, t time.Time, b bool) [][]*x509.Certificate {
	panic("implement me")
}

func (n poolCertVerifier) Verify(cert *x509.Certificate, moment time.Time) error {
	if n.pool == nil {
		return nil
	}
	_, err := cert.Verify(x509.VerifyOptions{Roots: n.pool, CurrentTime: moment})
	return err
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

func TestCrypto_GenerateVendorCACSR(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)


	t.Run("ok", func(t *testing.T) {
		csrAsBytes, err := client.GenerateVendorCACSR("BecauseWeCare B.V.")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, csrAsBytes)
		// Verify result is a valid PKCS10 CSR
		csr, err := x509.ParseCertificateRequest(csrAsBytes)
		if !assert.NoError(t, err) {
			return
		}
		// Verify signature
		err = csr.CheckSignature()
		if !assert.NoError(t, err) {
			return
		}

		t.Run("verify subject", func(t *testing.T) {
			assert.Equal(t, "CN=BecauseWeCare B.V. CA,O=BecauseWeCare B.V.,C=NL", csr.Subject.String())
		})
		t.Run("verify VendorID SAN", func(t *testing.T) {
			extension, err := CertificateRequest(*csr).getUniqueExtension("2.5.29.17")
			assert.NoError(t, err)
			assert.Equal(t, []byte{0x30, 0x14, 0xa0, 0x12, 0x6, 0x9, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x83, 0xac, 0x43, 0x4, 0xa0, 0x5, 0xc, 0x3, 0x31, 0x32, 0x33}, extension.Value)
		})
		t.Run("verify Domain extension", func(t *testing.T) {
			extension, err := CertificateRequest(*csr).getUniqueExtension("1.3.6.1.4.1.54851.3")
			assert.NoError(t, err)
			assert.Equal(t, "healthcare", strings.TrimSpace(string(extension.Value)))
		})
	})
	t.Run("ok - key exists", func(t *testing.T) {
		client.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{core.NutsConfig().Identity()}),  false)
		csr, err := client.GenerateVendorCACSR("BecauseWeCare B.V.")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, csr)
		// Verify result is a valid PKCS10 CSR
		parsedCSR, err := x509.ParseCertificateRequest(csr)
		if !assert.NoError(t, err) {
			return
		}
		// Verify signature
		err = parsedCSR.CheckSignature()
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("error - invalid name", func(t *testing.T) {
		csr, err := client.GenerateVendorCACSR("   ")
		assert.Nil(t, csr)
		assert.EqualError(t, err, "invalid name")
	})
}

func TestCrypto_StoreVendorCACertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)


	t.Run("ok - private key exists", func(t *testing.T) {
		client.GenerateKeyPair(key, false)
		privateKey, _ := client.GetPrivateKey(key)
		certificateAsBytes := test.GenerateCertificate(time.Now(), 1, privateKey)
		certificate, _ := x509.ParseCertificate(certificateAsBytes)
		err := client.StoreVendorCACertificate(certificate)
		assert.NoError(t, err)
	})
	t.Run("error - private key does not exist", func(t *testing.T) {
		client := createCrypto(t)
		createCrypto(t)

		privateKey, _ := client.generateKeyPair()
		certificateAsBytes := test.GenerateCertificate(time.Now(), 1, privateKey)
		certificate, _ := x509.ParseCertificate(certificateAsBytes)
		err := client.StoreVendorCACertificate(certificate)
		assert.EqualError(t, err, "private key not present for key: [urn:oid:1.3.6.1.4.1.54851.4:123|]")
	})
	t.Run("error - existing private key differs", func(t *testing.T) {
		client.GenerateKeyPair(key, true)
		privateKey, _ := client.GetPrivateKey(key)
		certificateAsBytes := test.GenerateCertificate(time.Now(), 1, privateKey)
		certificate, _ := x509.ParseCertificate(certificateAsBytes)
		client.GenerateKeyPair(key, true)
		err := client.StoreVendorCACertificate(certificate)
		assert.EqualError(t, err, "public key in certificate does not match stored private key (key: [urn:oid:1.3.6.1.4.1.54851.4:123|])")
	})
	t.Run("error - certificate is nil", func(t *testing.T) {
		err := client.StoreVendorCACertificate(nil)
		assert.EqualError(t, err, "certificate is nil")
	})
}

func TestCrypto_GetSigningCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 365*3)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)

	t.Run("ok - non existent", func(t *testing.T) {
		certificate, privateKey, err := client.GetSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
	t.Run("ok - exists", func(t *testing.T) {
		_, _, err := client.RenewSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		certificate, privateKey, err := client.GetSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)
	})
	t.Run("ok - exists but expired", func(t *testing.T) {
		privateKey, err := client.generateAndStoreKeyPair(key.WithQualifier(SigningCertificateQualifier), true)
		if !assert.NoError(t, err) {
			return
		}
		certificateAsASN1 := test.GenerateCertificate(time.Now().AddDate(-1, 0, 0), 1, privateKey)
		client.Storage.SaveCertificate(key.WithQualifier(SigningCertificateQualifier), certificateAsASN1)
		certificate, pk, err := client.GetSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, certificate)
		assert.Nil(t, pk)
	})
	t.Run("error - exists, missing private key", func(t *testing.T) {
		entity2 := types.LegalEntity{"foobar2"}
		key2 := types.KeyForEntity(entity2)
		privateKey, _ := client.generateKeyPair()
		certificateAsASN1 := test.GenerateCertificate(time.Now(), 1, privateKey)
		client.Storage.SaveCertificate(key2.WithQualifier(SigningCertificateQualifier), certificateAsASN1)
		certificate, pk, err := client.GetSigningCertificate(entity2)
		assert.Contains(t, err.Error(), "unable to retrieve private key for certificate: [foobar2|sign]: could not open entry [foobar2|sign] with filename")
		assert.Nil(t, certificate)
		assert.Nil(t, pk)
	})
}

func TestCrypto_RenewSigningCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 365*3)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)

	t.Run("ok", func(t *testing.T) {
		certificate, privateKey, err := client.RenewSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)
	})
}

func TestCrypto_issueSubCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 1)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)
	t.Run("ok", func(t *testing.T) {
		certificate, privateKey, err := client.issueSubCertificate(entity, "test", CertificateProfile{})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)

		// Verify SAN is copied from CA certificate
		var san pkix.Extension
		for _, extension := range certificate.Extensions {
			if cert.OIDSubjectAltName.Equal(extension.Id) {
				san = extension
			}
		}
		assert.False(t, san.Id.String() == "", "SAN not found")
		altName, err := cert.UnmarshalOtherSubjectAltName(cert.OIDNutsVendor, san.Value)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "Foobar", altName)
	})
	t.Run("error - CA certificate not found", func(t *testing.T) {
		certificate, privateKey, err := client.issueSubCertificate(types.LegalEntity{"foobar"}, "test", CertificateProfile{})
		assert.Contains(t, err.Error(), "unable to retrieve CA certificate [foobar|]: could not open entry [foobar|] with filename")
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
	t.Run("error - qualifier not set", func(t *testing.T) {
		_, _, err := client.issueSubCertificate(types.LegalEntity{}, "", CertificateProfile{})
		assert.EqualError(t, err, "missing qualifier")
	})
	t.Run("error - CA certificate subject missing country", func(t *testing.T) {
		_, _ = selfSignCACertificateEx(client, key, pkix.Name{
			Organization: []string{"Zorg Inc."},
		}, time.Now(), 1)
		certificate, privateKey, err := client.issueSubCertificate(entity, "test", CertificateProfile{})
		assert.EqualError(t, err, "subject of CA certificate [urn:oid:1.3.6.1.4.1.54851.4:123|] doesn't contain 'C' component")
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
	t.Run("error - CA certificate subject missing org", func(t *testing.T) {
		_, _ = selfSignCACertificateEx(client, key, pkix.Name{
			Country: []string{"NL"},
		}, time.Now(), 1)
		certificate, privateKey, err := client.issueSubCertificate(entity, "test", CertificateProfile{})
		assert.EqualError(t, err, "subject of CA certificate [urn:oid:1.3.6.1.4.1.54851.4:123|] doesn't contain 'O' component")
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
}

func TestCrypto_GetTLSCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 365*3)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)

	t.Run("ok - non existent", func(t *testing.T) {
		certificate, privateKey, err := client.GetTLSCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
	t.Run("ok - exists", func(t *testing.T) {
		_, _, err := client.RenewTLSCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		certificate, privateKey, err := client.GetTLSCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)
	})
}

func TestCrypto_RenewTLSCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 365*3)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)

	t.Run("ok", func(t *testing.T) {
		certificate, privateKey, err := client.RenewTLSCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)

		// Verify SAN is copied from CA certificate
		var san pkix.Extension
		for _, extension := range certificate.Extensions {
			if cert.OIDSubjectAltName.Equal(extension.Id) {
				san = extension
			}
		}
		assert.False(t, san.Id.String() == "", "SAN not found")
		altName, err := cert.UnmarshalOtherSubjectAltName(cert.OIDNutsVendor, san.Value)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "Foobar", altName)
	})
	t.Run("ok - certificate already exists", func(t *testing.T) {

	})
}

func TestCrypto_SignCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	ca := key
	client.GenerateKeyPair(ca, false)
	caPrivateKey, _ := client.GetPrivateKey(ca)
	endEntityKey := types.KeyForEntity(types.LegalEntity{URI: "End Entity"})
	intermediateCaKey := types.KeyForEntity(types.LegalEntity{URI: "Intermediate CA"})

	roots := x509.NewCertPool()

	t.Run("self-sign CSR", func(t *testing.T) {
		certificate, err := selfSignCACertificate(client, ca)
		if !assert.NoError(t, err) {
			return
		}
		containsExtension := false
		for _, ext := range certificate.Extensions {
			if reflect.DeepEqual(ext, extension) {
				containsExtension = true
			}
		}
		assert.True(t, containsExtension, "certificate doesn't contain custom extension")

		assert.True(t, certificate.IsCA)
		assert.Equal(t, 1, certificate.MaxPathLen)
		assert.Equal(t, ca.Owner(), certificate.Subject.CommonName)
		assert.Equal(t, ca.Owner(), certificate.Issuer.CommonName)
		roots.AddCert(certificate)
		verify, err := certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		})
		assert.NoError(t, err)
		assert.NotNil(t, verify)
	})

	t.Run("sign CSR for end-entity under root CA", func(t *testing.T) {
		// Setup
		root, _ := selfSignCACertificate(client, ca)
		roots.AddCert(root)
		client.GenerateKeyPair(endEntityKey, false)
		endEntityPrivKey, _ := client.GetPrivateKey(endEntityKey)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: endEntityKey.Owner()},
		}
		csr, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, endEntityPrivKey)
		// Sign
		certBytes, err := client.SignCertificate(endEntityKey, ca, csr, CertificateProfile{
			NumDaysValid: 1,
		})
		// Verify
		if !assert.NoError(t, err) {
			return
		}
		certificate, err := x509.ParseCertificate(certBytes)
		if !assert.NoError(t, err) {
			return
		}
		assert.False(t, certificate.IsCA)
		assert.Equal(t, 0, certificate.MaxPathLen)
		assert.Equal(t, endEntityKey.Owner(), certificate.Subject.CommonName)
		assert.Equal(t, ca.Owner(), certificate.Issuer.CommonName)
		verify, err := certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, verify)
	})

	t.Run("error - signing certificate is not a CA certificate", func(t *testing.T) {
		// Certificate created by GenerateCertificate is not a CA certificate
		caCertificate := test.GenerateCertificate(time.Now(), 1, caPrivateKey)
		err := client.Storage.SaveCertificate(ca, caCertificate)
		if !assert.NoError(t, err) {
			return
		}
		csrTemplate := x509.CertificateRequest{
			Subject:   pkix.Name{CommonName: endEntityKey.Owner()},
			PublicKey: caPrivateKey.Public(),
		}
		certBytes, err := client.signCertificate(&csrTemplate, ca, CertificateProfile{}, false)
		assert.EqualError(t, err, "CA certificate validation failed: certificate is not an CA certificate")
		assert.Nil(t, certBytes)
	})

	t.Run("error - validity period must be within CA certificate", func(t *testing.T) {
		// Setup
		root, _ := selfSignCACertificate(client, ca)
		roots.AddCert(root)
		client.GenerateKeyPair(endEntityKey, false)
		endEntityPrivKey, _ := client.GetPrivateKey(endEntityKey)
		csrTemplate := x509.CertificateRequest{
			Subject:   pkix.Name{CommonName: endEntityKey.Owner()},
			PublicKey: endEntityPrivKey.Public(),
		}
		t.Run("not before", func(t *testing.T) {
			certBytes, err := client.signCertificate(&csrTemplate, ca, CertificateProfile{
				NumDaysValid: 1,
				notAfter:     root.NotAfter,
				notBefore:    time.Unix(root.NotBefore.Unix()-1000, 0),
			}, false)
			assert.Contains(t, err.Error(), "CA certificate validation failed: certificate validity")
			assert.Nil(t, certBytes)
		})
		t.Run("not after", func(t *testing.T) {
			certBytes, err := client.signCertificate(&csrTemplate, ca, CertificateProfile{
				NumDaysValid: 1,
				notBefore:    root.NotBefore,
				notAfter:     time.Unix(root.NotAfter.Unix()+1000, 0),
			}, false)
			assert.Contains(t, err.Error(), "CA certificate validation failed: certificate validity")
			assert.Nil(t, certBytes)
		})
	})

	t.Run("sign CSR for intermediate CA", func(t *testing.T) {
		// Setup
		root, _ := selfSignCACertificate(client, ca)
		roots.AddCert(root)
		client.GenerateKeyPair(intermediateCaKey, false)
		intermediateCaPrivKey, _ := client.GetPrivateKey(intermediateCaKey)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: intermediateCaKey.Owner()},
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, intermediateCaPrivKey)
		if !assert.NoError(t, err) {
			return
		}
		// Sign
		certBytes, err := client.SignCertificate(intermediateCaKey, ca, csr, CertificateProfile{
			IsCA:         true,
			NumDaysValid: 1,
		})
		// Verify
		if !assert.NoError(t, err) {
			return
		}
		certificate, err := x509.ParseCertificate(certBytes)
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, certificate.IsCA)
		assert.False(t, certificate.MaxPathLenZero)
		assert.Equal(t, intermediateCaKey.Owner(), certificate.Subject.CommonName)
		assert.Equal(t, ca.Owner(), certificate.Issuer.CommonName)
		verify, err := certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, verify)
	})

	t.Run("invalid CSR: format", func(t *testing.T) {
		certificate, err := client.SignCertificate(endEntityKey, ca, []byte{1, 2, 3}, CertificateProfile{})
		assert.Contains(t, err.Error(), ErrUnableToParseCSR.Error())
		assert.Nil(t, certificate)
	})

	t.Run("invalid CSR: signature", func(t *testing.T) {
		client.GenerateKeyPair(key, false)
		endEntityPrivKey, _ := client.GetPrivateKey(endEntityKey)
		otherPrivKey, _ := client.GetPrivateKey(ca)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: endEntityKey.Owner()},
		}
		// Make this CSR invalid by providing a public key which doesn't match the private key
		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, opaquePrivateKey{
			signFn:    endEntityPrivKey.Sign,
			publicKey: otherPrivKey.Public(),
		})
		if !assert.NoError(t, err) {
			return
		}
		// Sign
		certificate, err := client.SignCertificate(endEntityKey, ca, csr, CertificateProfile{NumDaysValid: 1})
		assert.Contains(t, err.Error(), ErrCSRSignatureInvalid.Error())
		assert.Nil(t, certificate)
	})

	t.Run("unknown CA: private key missing", func(t *testing.T) {
		// Setup
		client := createCrypto(t)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: endEntityKey.Owner()},
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, caPrivateKey)
		if !assert.NoError(t, err) {
			return
		}
		// Sign
		certificate, err := client.SignCertificate(endEntityKey, types.KeyForEntity(types.LegalEntity{"foobar"}), csr, CertificateProfile{})
		// Verify
		assert.Contains(t, err.Error(), ErrUnknownCA.Error())
		assert.Nil(t, certificate)
	})

	t.Run("unknown CA: certificate missing", func(t *testing.T) {
		// Setup
		client := createCrypto(t)
		client.GenerateKeyPair(ca, false)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: endEntityKey.Owner()},
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, caPrivateKey)
		if !assert.NoError(t, err) {
			return
		}
		// Sign
		certificate, err := client.SignCertificate(endEntityKey, ca, csr, CertificateProfile{})
		// Verify
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), ErrUnknownCA.Error())
		}
		assert.Nil(t, certificate)
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
		assert.EqualError(t, err, "unable to generate new key pair for [TestCrypto_GenerateKeyPair/error_-_already_exists|]: it already exists and overwrite=false")
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

func TestCryptoConfig_TrustStore(t *testing.T) {
	createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		client := createCrypto(t)
		client.doConfigure()
		assert.NotNil(t, client.TrustStore())
	})
}

func TestCrypto_TrustStore(t *testing.T) {
	createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		client := createCrypto(t)
		client.doConfigure()
		assert.NotNil(t, client.TrustStore())
	})
}

func TestCrypto_decryptWithSymmetricKey(t *testing.T) {
	t.Run("nonce empty", func(t *testing.T) {
		_, err := decryptWithSymmetricKey(make([]byte, 0), aescbc.AesCbcHmac{}, make([]byte, 0))
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

func selfSignCACertificate(client Client, key types.KeyIdentifier) (*x509.Certificate, error) {
	return selfSignCACertificateEx(client, key, pkix.Name{CommonName: key.Owner()}, time.Now(), 365*3)
}

func selfSignCACertificateEx(client Client, key types.KeyIdentifier, name pkix.Name, notBefore time.Time, daysValid int) (*x509.Certificate, error) {
	subjectAltName, _ := cert.MarshalOtherSubjectAltName(cert.OIDNutsVendor, "Foobar")
	csrTemplate := x509.CertificateRequest{
		Subject: name,
		ExtraExtensions: []pkix.Extension{
			extension,
			{Id: cert.OIDSubjectAltName, Critical: false, Value: subjectAltName},
		},
	}
	privateKey, err := client.GetPrivateKey(key)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}
	certBytes, err := client.SignCertificate(key, key, csr, CertificateProfile{
		IsCA:       true,
		MaxPathLen: 1,
		notBefore:  notBefore,
		notAfter:   notBefore.AddDate(0, 0, daysValid),
	})
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func Test_symmetricKeyToBlockCipher(t *testing.T) {
	t.Run("error - invalid key size", func(t *testing.T) {
		c, err := symmetricKeyToBlockCipher([]byte{1, 2, 3})
		assert.Nil(t, c)
		assert.EqualError(t, err, "crypto/aes: invalid key size 3")
	})
}

type CertificateRequest x509.CertificateRequest

func (csr CertificateRequest) getUniqueExtension(oid string) (*pkix.Extension, error) {
	var result pkix.Extension
	for _, ext := range csr.Extensions {
		if ext.Id.String() == oid {
			if result.Id.String() != "" {
				return nil, fmt.Errorf("multiple extensions in certificate with OID: %s", oid)
			}
			result = ext
		}
	}
	if result.Id.String() == "" {
		return nil, fmt.Errorf("no extensions in certificate with OID: %s", oid)
	}
	return &result, nil
}