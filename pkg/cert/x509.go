package cert

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"sort"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	core "github.com/nuts-foundation/nuts-go-core"
)

// SerialNumber generates a random serialNumber
// Taken from crypto/tls/generate_cert.go
func SerialNumber() (*big.Int, error) {
	snLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, snLimit)
}

// GetCertificate converts the given JWK to a X.509 certificate chain, returning the topmost certificate. If the JWK
// does not contain any certificates, nil is returned.
func GetCertificate(jwkAsMap interface{}) *x509.Certificate {
	chain, err := jwkMapToCertChain(jwkAsMap)
	if err != nil {
		return nil
	}
	if len(chain) == 0 {
		return nil
	}
	return chain[0]
}

// GetActiveCertificates converts the given JWKs to X509 certificates and returns them sorted,
// longest valid certificate first. Expired certificates aren't returned.
func GetActiveCertificates(jwks []interface{}, instant time.Time) []*x509.Certificate {
	var activeCertificates []*x509.Certificate
	for _, keyAsMap := range jwks {
		certificate := GetCertificate(keyAsMap)
		if certificate == nil || instant.Before(certificate.NotBefore) || instant.After(certificate.NotAfter) {
			continue
		}
		activeCertificates = append(activeCertificates, certificate)
	}
	sort.Slice(activeCertificates, func(i, j int) bool {
		first := activeCertificates[i]
		second := activeCertificates[j]
		return first.NotAfter.UnixNano()-instant.UnixNano() > second.NotAfter.UnixNano()-instant.UnixNano()
	})
	return activeCertificates
}

func jwkMapToCertChain(keyAsMap interface{}) ([]*x509.Certificate, error) {
	key, err := MapToJwk(keyAsMap.(map[string]interface{}))
	if err != nil {
		return nil, err
	}
	chainInterf, exists := key.Get("x5c")
	if !exists {
		// JWK does not contain x5c component (X.509 certificate chain)
		return nil, errors.New("JWK has no x5c field")
	}
	return chainInterf.(jwk.CertificateChain).Get(), nil
}

// The structs below look funky, but are required to marshal SubjectAlternativeName.otherName the same way OpenSSL does.
type otherNameValue struct {
	Value asn1.RawValue
}
type otherNameTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value otherNameValue `asn1:"tag:0"`
}
type otherName struct {
	TypeAndValue otherNameTypeAndValue `asn1:"tag:0"`
}

func MarshalOtherSubjectAltName(valueType asn1.ObjectIdentifier, value string) ([]byte, error) {
	return asn1.Marshal(otherName{TypeAndValue: otherNameTypeAndValue{
		Type:  valueType,
		Value: otherNameValue{asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(value)}},
	}})
}

// UnmarshalOtherSubjectAltName tries to unmarshal an SubjectAlternativeName otherName entry (marshalled by MarshalOtherSubjectAltName)
// with the given OID type (valueType). It returns the value as string. If an otherName with the given type wasn't found,
// an empty string is returned. If an errors occurs during unmarshalling, it is returned.
func UnmarshalOtherSubjectAltName(valueType asn1.ObjectIdentifier, data []byte) (string, error) {
	value := otherName{}
	if _, err := asn1.Unmarshal(data, &value); err != nil {
		return "", err
	}
	if !value.TypeAndValue.Type.Equal(valueType) {
		return "", nil
	}
	return string(value.TypeAndValue.Value.Value.Bytes), nil
}

func MarshalNutsDomain(domain string) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Tag:   asn1.TagUTF8String,
		Bytes: []byte(domain),
	})
}

// UnmarshalNutsDomain tries to unmarshal the ASN.1 encoded Nuts Domain extension in a X.509 certificate.
// It returns the value as a string, or an error if one occurs.
func UnmarshalNutsDomain(data []byte) (string, error) {
	value := asn1.RawValue{}
	if _, err := asn1.Unmarshal(data, &value); err != nil {
		return "", err
	}
	return string(value.Bytes), nil
}

var ErrSANNotFound = errors.New("subject alternative name not found")

// VendorIDFromCertificate returns the Nuts Vendor ID from a certificate.
func VendorIDFromCertificate(certificate *x509.Certificate) (core.PartyID, error) {
	// extract SAN
	var vendor string
	for _, e := range certificate.Extensions {
		if e.Id.Equal(OIDSubjectAltName) {
			// for multiple SAN values, only return if the Nuts Vendor can be found
			if vendor, _ = UnmarshalOtherSubjectAltName(OIDNutsVendor, e.Value); vendor != "" {
				break
			}
		}
	}
	if vendor == "" {
		return core.PartyID{}, ErrSANNotFound
	}

	return core.NewPartyID(core.NutsVendorOID, vendor)
}

// DomainFromCertificate finds the Nuts domain without the OID, just the value
func DomainFromCertificate(certificate *x509.Certificate) (string, error) {
	// extract SAN
	for _, e := range certificate.Extensions {
		if e.Id.Equal(OIDNutsDomain) {
			return UnmarshalNutsDomain(e.Value)
		}
	}
	return "", ErrSANNotFound
}
