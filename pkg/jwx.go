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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	errors2 "github.com/pkg/errors"
)

// ErrUnsupportedSigningKey is returned when an unsupported private key is used to sign. Currently only ecdsa and rsa keys are supported
var ErrUnsupportedSigningKey = errors.New("signing key algorithm not supported")

// jwsAlgorithm holds the supported (required) JWS signing algorithm
const jwsAlgorithm = jwa.RS256

// PublicKeyInJWK loads the key from storage and wraps it in a Key format. Supports RSA, ECDSA and Symmetric style keys
func (client *Crypto) GetPublicKeyAsJWK(key types.KeyIdentifier) (jwk.Key, error) {
	pubKey, err := client.Storage.GetPublicKey(key)

	if err != nil {
		return nil, err
	}

	return jwk.New(pubKey)
}

// SignJwtFor creates a signed JWT given a legalEntity and map of claims
func (client *Crypto) SignJWT(claims map[string]interface{}, key types.KeyIdentifier) (token string, err error) {
	rsaPrivateKey, err := client.Storage.GetPrivateKey(key)

	if err != nil {
		return "", err
	}

	token, err = SignJWT(rsaPrivateKey, claims, nil)
	return
}

// SignJWTRFC003 signs a JWT according to Nuts RFC003. This func is only for signing the bearer token of the oauth flow.
func (client *Crypto) SignJWTRFC003(claims map[string]interface{}) (token string, err error) {
	var (
		certificate *x509.Certificate
		privateKey  crypto.Signer
	)
	if certificate, privateKey, err = client.generateVendorEphemeralSigningCertificate(); err != nil {
		return
	}

	chain := cert.MarshalX509CertChain([]*x509.Certificate{certificate})
	additionalHeaders := map[string]interface{}{
		"x5c": chain,
	}

	token, err = SignJWT(privateKey, claims, additionalHeaders)
	return
}

func (client Crypto) SignJWS(payload []byte, key types.KeyIdentifier) ([]byte, error) {
	certificate, privateKey, err := client.getCertificateAndKey(key)
	if err != nil {
		return nil, errors2.Wrapf(err, "error while retrieving signing certificate and key (%s)", key)
	}
	if certificate == nil || privateKey == nil {
		return nil, fmt.Errorf("signing certificate and/or private not present: %s", key)
	}
	if err := cert.ValidateCertificate(certificate, cert.MeantForSigning()); err != nil {
		return nil, err
	}
	headers := jws.NewHeaders()
	headers.Set(jws.X509CertChainKey, cert.MarshalX509CertChain([]*x509.Certificate{certificate}))
	return jws.Sign(payload, jwsAlgorithm, privateKey, jws.WithHeaders(headers))
}

func (client Crypto) SignJWSEphemeral(payload []byte, caKey types.KeyIdentifier, csr x509.CertificateRequest, signingTime time.Time) ([]byte, error) {
	// Generate ephemeral key and certificate
	entityPrivateKey, err := client.generateKeyPair()
	if err != nil {
		return nil, err
	}
	csr.PublicKey = &entityPrivateKey.PublicKey
	asn1Cert, err := client.signCertificate(&csr, caKey, CertificateProfile{
		KeyUsage:  x509.KeyUsageDigitalSignature,
		notBefore: signingTime,
		notAfter:  signingTime.Add(time.Minute),
	}, false)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(asn1Cert)
	if err != nil {
		return nil, err
	}
	// Now sign
	headers := jws.NewHeaders()
	headers.Set(jws.X509CertChainKey, cert.MarshalX509CertChain([]*x509.Certificate{certificate}))
	return jws.Sign(payload, jwsAlgorithm, entityPrivateKey, jws.WithHeaders(headers))
}

func (client *Crypto) VerifyJWS(signature []byte, signingTime time.Time, certVerifier cert.Verifier) ([]byte, error) {
	m, err := jws.ParseString(string(signature))
	if err != nil {
		return nil, errors2.Wrap(err, "unable to parse signature")
	}
	if len(m.Signatures()) == 0 {
		return nil, errors.New("JWS contains no signatures")
	}
	if len(m.Signatures()) > 1 {
		return nil, errors.New("JWS contains more than 1 signature")
	}

	sig := m.Signatures()[0]
	if sig.ProtectedHeaders().Algorithm() != jwsAlgorithm {
		return nil, fmt.Errorf("JWS is signed with incorrect algorithm (expected = %v, actual = %v)", jwsAlgorithm, sig.ProtectedHeaders().Algorithm())
	}

	// Parse X509 certificate chain
	certChain, err := cert.GetX509ChainFromHeaders(sig.ProtectedHeaders())
	if err != nil {
		return nil, ErrInvalidCertChain
	}

	if len(certChain) == 0 {
		return nil, fmt.Errorf("JWK doesn't contain X509 chain header (%s) header", jws.X509CertChainKey)
	}
	signingCert := certChain[0]
	// Check key strength. Cast should be safe since we checked the algorithm.
	if signingPubKey, ok := signingCert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("invalid key type, expected *rsa.PublicKey")
	} else if err := client.verifyKeySize(signingPubKey.Size() * 8); err != nil {
		return nil, err
	}
	// Check certificate is trusted
	if err := certVerifier.Verify(signingCert, signingTime, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}); err != nil {
		return nil, errors2.Wrap(err, ErrCertificateNotTrusted.Error())
	}
	// Check if the KeyUsage of the certificate is applicable for signing
	if err := cert.ValidateCertificate(signingCert, cert.MeantForSigning()); err != nil {
		return nil, err
	}
	// TODO: CRL checking
	return jws.Verify(signature, sig.ProtectedHeaders().Algorithm(), signingCert.PublicKey)
}

// VerifyWith verfifies a signature of some data with a given PublicKeyInPEM. It uses the SHA256 hashing function.
func (client *Crypto) VerifyWith(data []byte, sig []byte, key jwk.Key) (bool, error) {
	hashedData := sha256.Sum256(data)

	var mKey interface{}
	err := key.Raw(&mKey)
	if err != nil {
		return false, err
	}

	if k, ok := mKey.(*rsa.PublicKey); ok {
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, hashedData[:], sig); err != nil {
			return false, err
		}
		return true, nil
	}

	// todo support EC sigs
	//if k, ok := mKey.(*ecdsa.PublicKey); ok {
	//	if err := ecdsa.Verify(k, crypto.SHA256, hashedData[:], sig); err != nil {
	//		return false, err
	//	}
	//	return true, nil
	//}

	return false, ErrInvalidAlgorithm
}

// SignJWT signs claims with the signer and returns the compacted token. The headers param can be used to add additional headers
func SignJWT(signer crypto.Signer, claims map[string]interface{}, headers map[string]interface{}) (sig string, err error) {
	c := jwt.MapClaims{}
	for k, v := range claims {
		c[k] = v
	}

	// the current version of the used JWT lib doesn't support the crypto.Signer interface. The 4.0.0 version will.
	switch signer.(type) {
	case *rsa.PrivateKey:
		token := jwt.NewWithClaims(jwt.SigningMethodPS256, c)
		addHeaders(token, headers)
		sig, err = token.SignedString(signer.(*rsa.PrivateKey))
	case *ecdsa.PrivateKey:
		key := signer.(*ecdsa.PrivateKey)
		var method *jwt.SigningMethodECDSA
		if method, err = ecSigningMethod(key); err != nil {
			return
		}
		token := jwt.NewWithClaims(method, c)
		addHeaders(token, headers)
		sig, err = token.SignedString(signer.(*ecdsa.PrivateKey))
	default:
		err = errors.New("unsupported signing private key")
	}

	return
}

func addHeaders(token *jwt.Token, headers map[string]interface{}) {
	if headers == nil {
		return
	}

	for k, v := range headers {
		token.Header[k] = v
	}
}

func ecSigningMethod(key *ecdsa.PrivateKey) (method *jwt.SigningMethodECDSA, err error) {
	switch key.Params().BitSize {
	case 256:
		method = jwt.SigningMethodES256
	case 384:
		method = jwt.SigningMethodES384
	case 521:
		method = jwt.SigningMethodES512
	default:
		err = ErrUnsupportedSigningKey
	}
	return
}
