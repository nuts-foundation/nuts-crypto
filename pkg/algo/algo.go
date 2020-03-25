package algo

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Recommended:
// ECDSA_WITH_AES_256_GCM_SHA384
// ECDSA_WITH_CHACHA20_POLY1305_SHA256
// ECDSA_WITH_AES_128_GCM_SHA256
// RSA_WITH_AES_256_GCM_SHA384
// RSA_WITH_CHACHA20_POLY1305_SHA256
// RSA_WITH_AES_128_GCM_SHA256

// Additionally supported:
// ECDSA_WITH_AES_256_CBC_SHA384
// ECDSA_WITH_AES_256_CBC_SHA
// ECDSA_WITH_AES_128_CBC_SHA256
// ECDSA_WITH_AES_128_CBC_SHA
// RSA_WITH_AES_256_CBC_SHA384
// RSA_WITH_AES_256_CBC_SHA
// RSA_WITH_AES_128_CBC_SHA256
// RSA_WITH_AES_128_CBC_SHA
// RSA_WITH_AES_256_GCM_SHA384
// RSA_WITH_CHACHA20_POLY1305_SHA256
// RSA_WITH_AES_128_GCM_SHA256
// RSA_WITH_AES_256_CBC_SHA256
// RSA_WITH_AES_256_CBC_SHA
// RSA_WITH_AES_128_CBC_SHA256
// RSA_WITH_AES_128_CBC_SHA

// We prefer EC keys, so it should be first in the array
var keyFamilies = []KeyFamily{getECKeyFamily(), getRSAKeyFamily()}

type keyFamily struct {
	name          string
	recommendedKT []KeyType
	// supportedKT should include recommendedKT plus non-recommended but supported key types
	supportedKT   []KeyType
	recommendedSA []SigningAlgorithm
	// supportedSA should include recommendedSA plus non-recommended but supported algorithms
	supportedSA []SigningAlgorithm
}

func (e keyFamily) Name() string {
	return e.name
}

func (e keyFamily) RecommendedKeyTypes() []KeyType {
	// Clone slice as to avoid having the caller (accidentally) mutate the internal state.
	return append([]KeyType{}, e.recommendedKT...)
}

func (e keyFamily) SupportedKeyTypes() []KeyType {
	// Clone slice as to avoid having the caller (accidentally) mutate the internal state.
	return append([]KeyType{}, e.supportedKT...)
}

func (e keyFamily) RecommendedSigningAlgorithms() []SigningAlgorithm {
	// Clone slice as to avoid having the caller (accidentally) mutate the internal state.
	return append([]SigningAlgorithm{}, e.recommendedSA...)
}

func (e keyFamily) SupportedSigningAlgorithms() []SigningAlgorithm {
	// Clone slice as to avoid having the caller (accidentally) mutate the internal state.
	return append([]SigningAlgorithm{}, e.supportedSA...)
}

func (e keyFamily) IsKeySupported(key interface{}) bool {
	for _, kt := range e.supportedKT {
		if kt.Matches(key) {
			return true
		}
	}
	return false
}

// The recommended key types and algorithms are those that are recommended by the Dutch NCSC (Nationaal Cyber Security Centrum)
// and supported as JWA (JSON Web Algorithm, RFC 7518).

func RecommendedKeyTypes() []KeyType {
	var kts []KeyType
	for _, fam := range keyFamilies {
		for _, kt := range fam.RecommendedKeyTypes() {
			kts = append(kts, kt)
		}
	}
	return kts
}

func SupportedKeyTypes() []KeyType {
	var kts []KeyType
	for _, fam := range keyFamilies {
		for _, kt := range fam.SupportedKeyTypes() {
			kts = append(kts, kt)
		}
	}
	return kts
}

func RecommendedSigningAlgorithms() []SigningAlgorithm {
	var kts []SigningAlgorithm
	for _, fam := range keyFamilies {
		for _, kt := range fam.RecommendedSigningAlgorithms() {
			kts = append(kts, kt)
		}
	}
	return kts
}

func SupportedSigningAlgorithms() []SigningAlgorithm {
	var kts []SigningAlgorithm
	for _, fam := range keyFamilies {
		for _, kt := range fam.SupportedSigningAlgorithms() {
			kts = append(kts, kt)
		}
	}
	return kts
}

func RecommendedSigningAlgorithm(key interface{}) (SigningAlgorithm, error) {
	for _, fam := range keyFamilies {
		if fam.IsKeySupported(key) {
			return fam.RecommendedSigningAlgorithms()[0], nil
		}
	}
	return nil, fmt.Errorf("no supported signing algorithms for key: %T", key)
}

func GetKeyTypeFromKey(key interface{}) (KeyType, error) {
	for _, fam := range keyFamilies {
		for _, kt := range fam.SupportedKeyTypes() {
			if kt.Matches(key) {
				return kt, nil
			}
		}
	}
	return nil, UnsupportedKeyTypeError(key)
}

func GetKeyTypeFromIdentifier(identifier string)  (KeyType, error) {
	for _, kt := range SupportedKeyTypes() {
		if kt.Identifier() == identifier {
			return kt, nil
		}
	}
	return nil, UnsupportedKeyTypeError(identifier)
}

func encodeASN1(asn1data []byte, header string) string {
	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  header,
		Bytes: asn1data,
	})
	return string(bytes)
}

func GetPublicKey(key interface{}) interface{} {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

func UnmarshalPEM(src string) (interface{}, error) {
	block, _ := pem.Decode([]byte(src))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if strings.Contains(block.Type, "PUBLIC KEY") {
		return x509.ParsePKIXPublicKey(block.Bytes)
	}
	if strings.Contains(block.Type, "PRIVATE KEY") {
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	return nil, UnsupportedKeyTypeError(block.Type)
}

func SigningAlgorithmFromJWAIdentifier(jwaIdentifier string) SigningAlgorithm {
	for _, algo := range SupportedSigningAlgorithms() {
		if algo.JWAIdentifier() == jwaIdentifier {
			return algo
		}
	}
	return nil
}

type signingAlgorithm struct {
	jwa string
}

func (s signingAlgorithm) JWAIdentifier() string {
	return s.jwa
}
