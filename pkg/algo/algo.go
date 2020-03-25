package algo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
var keyTypes = append(getECKeyTypes(), getRSAKeyTypes()...)

// SupportedKeyTypes returns the recommended key types and algorithms are those that are recommended by the Dutch NCSC (Nationaal Cyber Security Centrum)
// supported as JWA (JSON Web Algorithm, RFC 7518) and supported by Corda.
func SupportedKeyTypes() []KeyType {
	// Clone to avoid modifications by callers
	return append(keyTypes)
}

func GetKeyTypeFromKey(key interface{}) (KeyType, error) {
	for _, kt := range keyTypes {
		if kt.Matches(key) {
			return kt, nil
		}
	}
	return nil, UnsupportedKeyTypeError(key)
}

func GetKeyTypeFromIdentifier(identifier string) (KeyType, error) {
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
	for _, kt := range keyTypes {
		if kt.SigningAlgorithm().JWAIdentifier() == jwaIdentifier {
			return kt.SigningAlgorithm()
		}
	}
	return nil
}

func doHash(h crypto.Hash, data []byte) []byte {
	digest := h.New()
	digest.Write(data)
	d := digest.Sum(nil)
	return d
}
