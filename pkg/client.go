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
	"crypto"
	"crypto/x509"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"time"
)

// CryptoClient defines the functions than can be called by a Cmd, Direct or via rest call.
type Client interface {
	// DecryptKeyAndCipherText decrypts a cipherText using the given key (private key must be present).
	DecryptKeyAndCipherText(cipherText types.DoubleEncryptedCipherText, key types.KeyIdentifier) ([]byte, error)
	// EncryptKeyAndPlainText encrypts a piece of data for the given public keys
	EncryptKeyAndPlainText(plainText []byte, keys []jwk.Key) (types.DoubleEncryptedCipherText, error)
	// CalculateExternalId calculates an externalId for a (custodian, subject, actor) triple using the given key (private key must be present).
	CalculateExternalId(subject string, actor string, key types.KeyIdentifier) ([]byte, error)
	// GenerateKeyPair generates a key pair. If the key already exists, it is overwritten and associated certificates are removed.
	GenerateKeyPair(key types.KeyIdentifier) (crypto.PublicKey, error)
	// SignFor signs a piece of data using the given key (private key must be present).
	Sign(data []byte, key types.KeyIdentifier) ([]byte, error)
	// SignCertificate issues a certificate by signing a PKCS10 certificate request. The private key of the specified CA should be available in the key store.
	SignCertificate(subjectKey types.KeyIdentifier, caKey types.KeyIdentifier, pkcs10 []byte, profile CertificateProfile) ([]byte, error)
	// GetPrivateKey returns the specified private key (for e.g. signing) in non-exportable form.
	GetPrivateKey(key types.KeyIdentifier) (crypto.Signer, error)
	// VerifyWith verifies a signature for a given jwk
	VerifyWith(data []byte, sig []byte, jwk jwk.Key) (bool, error)
	// GetTLSCertificate retrieves a TLS certificate which is issued under the given key. If there's no TLS certificate for the
	// given entity or it has expired, a new certificate will be issued. As such, the key MUST be a Certificate Authority
	// or otherwise an error will be returned.
	//
	// If all goes well, the TLS certificate is returned alongside the corresponding private key.
	GetTLSCertificate(caKey types.KeyIdentifier) (*x509.Certificate, crypto.PrivateKey, error)
	// GetPublicKeyAsPEM returns the PEM encoded PublicKey
	GetPublicKeyAsPEM(key types.KeyIdentifier) (string, error)
	// GetPublicKeyAsJWK returns the JWK encoded PublicKey for a given legal entity
	GetPublicKeyAsJWK(key types.KeyIdentifier) (jwk.Key, error)
	// SignJWT creates a signed JWT using the given key and map of claims (private key must be present).
	SignJWT(claims map[string]interface{}, key types.KeyIdentifier) (string, error)
	// SignJWSEphemeral signs payload according to the JWS spec with a temporary key and certificate which are generated just for this operation.
	// In other words, the key and certificate are not stored and cannot be used for any other cryptographic operation.
	// The certificate's validity is as short as possible, just spanning the instant of signing.
	//  payload:     data to be signed
	//  caKey:       key of the Certificate Authority which should issue the certificate (private key and certificate must be present).
	//  csr:         Certificate Signing Request which is used for issuing the X.509 certificate which is included in the JWS.
	//               The CSR indicates which entity (e.g. vendor, organization, etc) is signing the payload.
	//  signingTime: instant which is checked later when verifying the signature. The certificate will just span this instant.
	SignJWSEphemeral(payload []byte, caKey types.KeyIdentifier, csr x509.CertificateRequest, signingTime time.Time) ([]byte, error)
	// VerifyJWS verifies a JWS ("signature"): it parses the JWS, checks if it's been signed with the expected algorithm,
	// if it's signed with a certificate supplied in the "x5c" field of the JWS, if the certificate is trusted according
	// to the certificate verifier and whether the certificate was valid at the time of signing ("signingTime").
	// If the verification succeeds the payload that the JWS protects is returned.
	// If any of the verifications fail an error is returned (and no payload).
	VerifyJWS(signature []byte, signingTime time.Time, certVerifier cert.Verifier) ([]byte, error)
	// PrivateKeyExists returns if the specified private key eixsts.
	PrivateKeyExists(key types.KeyIdentifier) bool
	// TrustStore returns the trust store backing the crypto module.
	TrustStore() cert.TrustStore
}

// CertificateProfile is used to specify input parameters for certificate issuance.
type CertificateProfile struct {
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	IsCA        bool
	// MaxPathLen is ignored when IsCa = false
	MaxPathLen int
	// NumDaysValid is the number of days the certificate is valid, starting today
	NumDaysValid int
	// notBefore overrides (if also notAfter has been set) the NumDaysValid property.
	notBefore time.Time
	notAfter  time.Time
}

// NewCryptoClient returns a CryptoClient which either resolves call directly to the engine or uses a REST client.
func NewCryptoClient() Client {
	// todo: use configuration to choose client
	instance := CryptoInstance()
	if err := instance.Configure(); err != nil {
		panic(err)
	}
	return instance
}
