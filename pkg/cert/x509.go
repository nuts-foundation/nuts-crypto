package cert

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"sort"
	"time"
)

// GetActiveCertificates converts the given JWKs to X509 certificates and returns them sorted,
// longest valid certificate first. Expired certificates aren't returned.
func GetActiveCertificates(jwks []interface{}, instant time.Time) []*x509.Certificate {
	var activeCertificates []*x509.Certificate
	for _, keyAsMap := range jwks {
		chain, err := jwkMapToCertChain(keyAsMap)
		if err != nil {
			continue
		}
		if len(chain) == 0 {
			continue
		}
		certificate := chain[0]
		if instant.Before(certificate.NotBefore) || instant.After(certificate.NotAfter) {
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
	key, err := crypto.MapToJwk(keyAsMap.(map[string]interface{}))
	if err != nil {
		return nil, err
	}
	chainInterf, exists := key.Get("x5c")
	if !exists {
		// JWK does not contain x5c component (X.509 certificate chain)
		return nil, errors.New("JWK has no x5c field")
	}
	return chainInterf.([]*x509.Certificate), nil
}



func MarshalOtherSubjectAltName(valueType asn1.ObjectIdentifier, value string) ([]byte, error) {
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
	return asn1.Marshal(otherName{TypeAndValue: otherNameTypeAndValue{
		Type:  valueType,
		Value: otherNameValue{asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(value)}},
	}})
}

func MarshalNutsDomain(domain string) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Tag:   asn1.TagUTF8String,
		Bytes: []byte(domain),
	})
}
