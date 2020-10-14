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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	core "github.com/nuts-foundation/nuts-go-core"
	errors2 "github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// ErrWrongPublicKey indicates a wrong public key format
var ErrWrongPublicKey = core.NewError("failed to decode PEM block containing public key, key is of the wrong type", false)

// ErrWrongPrivateKey indicates a wrong private key format
var ErrWrongPrivateKey = core.NewError("failed to decode PEM block containing private key", false)

// ErrRsaPubKeyConversion indicates a public key could not be converted to an RSA public key
var ErrRsaPubKeyConversion = core.NewError("Unable to convert public key to RSA public key", false)

// ErrWrongPublicKey indicates a wrong certificate format
var ErrInvalidCertificate = core.NewError("failed to decode PEM block containing certificate", false)

// PemToPublicKey converts a PEM encoded public key to an rsa.PublicKeyInPEM
func PemToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, ErrWrongPublicKey
	}

	b := block.Bytes
	key, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	finalKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, ErrRsaPubKeyConversion
	}

	return finalKey, nil
}

// PublicKeyToPem converts an rsa.PublicKeyInPEM to PEM encoding
func PublicKeyToPem(pub crypto.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)

	if err != nil {
		return "", err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return string(pubBytes), err
}

// PemToSigner converts a PEM encoded private key to a Signer interface. It supports EC, RSA and PKIX PEM encoded strings
func PemToSigner(bytes []byte) (signer crypto.Signer, err error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		err = ErrWrongPrivateKey
		return
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		signer, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		signer, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var key interface{}
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		switch key.(type) {
		case *rsa.PrivateKey:
			signer = key.(*rsa.PrivateKey)
		case *ecdsa.PrivateKey:
			signer = key.(*ecdsa.PrivateKey)
		case ed25519.PrivateKey:
			signer = key.(ed25519.PrivateKey)
		}
	}
	return
}

// MapToJwk transforms a Jwk in map structure to a Jwk Key. The map structure is a typical result from json deserialization.
func MapToJwk(jwkAsMap map[string]interface{}) (jwk.Key, error) {
	set, err := MapsToJwkSet([]map[string]interface{}{jwkAsMap})
	if err != nil {
		return nil, err
	}
	return set.Keys[0], nil
}

// MapsToJwkSet transforms JWKs in map structures to a JWK set, just like MapToJwk.
func MapsToJwkSet(maps []map[string]interface{}) (*jwk.Set, error) {
	set := &jwk.Set{Keys: make([]jwk.Key, len(maps))}
	for i, m := range maps {
		jwkBytes, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		key, err := jwk.ParseKey(jwkBytes)
		if err != nil {
			return nil, err
		}
		set.Keys[i] = key
	}
	return set, nil
}

// ValidateJWK tests whether the given map (all) can is a parsable representation of a JWK. If not, an error is returned.
// If nil is returned, all supplied maps are parsable as JWK.
func ValidateJWK(maps ...interface{}) error {
	var stringMaps []map[string]interface{}
	for _, currMap := range maps {
		keyAsMap, ok := currMap.(map[string]interface{})
		if !ok {
			return errors.New("invalid JWK, it is not map[string]interface{}")
		}
		stringMaps = append(stringMaps, keyAsMap)
	}
	if _, err := MapsToJwkSet(stringMaps); err != nil {
		return errors2.Wrap(err, "invalid JWK")
	}
	return nil
}

// deepCopyMap is needed since the jwkSet.extractMap consumes the contents
func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cp[k] = deepCopyMap(vm)
		} else {
			cp[k] = v
		}
	}
	return cp
}

// JwkToMap transforms a Jwk key to a map. Can be used for json serialization
func JwkToMap(key jwk.Key) (map[string]interface{}, error) {
	return key.AsMap(context.Background())
}

// PemToJwk transforms pem to jwk for PublicKey
func PemToJwk(pub []byte) (jwk.Key, error) {
	pk, err := PemToPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return jwk.New(pk)
}

// CertificateToJWK constructs a new JWK based on the given X.509 certificate.
func CertificateToJWK(cert *x509.Certificate) (jwk.Key, error) {
	key, err := jwk.New(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	err = key.Set(jwk.X509CertChainKey, base64.StdEncoding.EncodeToString(cert.Raw))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func MapToX509CertChain(jwkAsMap map[string]interface{}) ([]*x509.Certificate, error) {
	key, err := MapToJwk(jwkAsMap)
	if err != nil {
		return nil, err
	}
	return key.X509CertChain(), nil
}

// GetX509ChainFromHeaders tries to retrieve the X.509 certificate chain ("x5c") from the JWK/JWS and parse it.
// If it doesn't contain the "x5c" header, nil is returned. If the header is present but it couldn't be parsed,
// an error is returned.
func GetX509ChainFromHeaders(headers jwkHeaderReader) ([]*x509.Certificate, error) {
	chainInterf, _ := headers.Get(jwk.X509CertChainKey)
	if chainInterf == nil {
		return nil, nil
	}
	var chain []*x509.Certificate
	for _, certStr := range chainInterf.([]string) {
		rawCert, err := base64.StdEncoding.DecodeString(certStr)
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// PemToX509 decodes PEM data as bytes to a *x509.Certificate
func PemToX509(rawData []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(rawData)
	if len(rest) > 0 {
		return nil, errors2.Wrapf(ErrInvalidCertificate, "found %d rest bytes after decoding PEM", len(rest))
	}
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidCertificate
	}
	return x509.ParseCertificate(block.Bytes)
}

func CertificateToPEM(certificate *x509.Certificate) string {
	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})
	return string(bytes)
}

// CopySANs copies the Subject Alternative Name extensions from the certificate and returns them as a new slice.
func CopySANs(certificate *x509.Certificate) []pkix.Extension {
	sans := make([]pkix.Extension, 0)
	for _, extension := range certificate.Extensions {
		if OIDSubjectAltName.Equal(extension.Id) {
			sans = append(sans, extension)
		}
	}
	return sans
}

type CertificateValidator func(*x509.Certificate) error

// ValidAt validator tests whether a certificate's validity spans the given moment in time.
func ValidAt(moment time.Time) CertificateValidator {
	return func(certificate *x509.Certificate) error {
		if moment.After(certificate.NotAfter) || moment.Before(certificate.NotBefore) {
			return fmt.Errorf("certificate is not valid at %s", moment)
		}
		return nil
	}
}

// ValidBetween validator tests whether a certificate's validity spans the given date/time window (bounds are inclusive).
func ValidBetween(startInclusive time.Time, endInclusive time.Time) CertificateValidator {
	return func(certificate *x509.Certificate) error {
		if startInclusive.Before(certificate.NotBefore) || endInclusive.After(certificate.NotAfter) {
			return fmt.Errorf("certificate validity (not before=%s, not after=%s) must span (start=%s, end=%s)", certificate.NotBefore, certificate.NotAfter, startInclusive, endInclusive)
		}
		return nil
	}
}

// IsCA validator tests whether a certificate is a CA certificate
func IsCA() CertificateValidator {
	return func(certificate *x509.Certificate) error {
		if !certificate.IsCA {
			return errors.New("certificate is not an CA certificate")
		}
		return nil
	}
}

func ValidateCertificate(certificate *x509.Certificate, validators ...CertificateValidator) error {
	if certificate == nil {
		return errors.New("certificate is nil")
	}
	for _, validator := range validators {
		if err := validator(certificate); err != nil {
			return err
		}
	}
	return nil
}

// MeantForSigning validates whether the certificate is meant for signing (key usage includes digitalSignature and/or contentCommitment)
func MeantForSigning() CertificateValidator {
	return func(certificate *x509.Certificate) error {
		if certificate.KeyUsage&x509.KeyUsageDigitalSignature != x509.KeyUsageDigitalSignature && certificate.KeyUsage&x509.KeyUsageContentCommitment != x509.KeyUsageContentCommitment {
			return errors.New("certificate is not meant for signing (keyUsage = digitalSignature | contentCommitment)")
		}
		return nil
	}
}

func unmarshalX509CertChain(chain []string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(chain))
	for idx, entry := range chain {
		asn1cert, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(asn1cert)
		if err != nil {
			return nil, err
		}
		certs[idx] = cert
	}
	return certs, nil
}

func MarshalX509CertChain(chain []*x509.Certificate) []string {
	encodedCerts := make([]string, len(chain))
	for idx, cert := range chain {
		encodedCerts[idx] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return encodedCerts
}

type jwkHeaderReader interface {
	Get(string) (interface{}, bool)
}
