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
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/lestrrat-go/jwx/jwk"
	"math/big"
	"time"
)

func decryptWithPrivateKey(cipherText []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func decryptWithSymmetricKey(cipherText []byte, key cipher.AEAD, nonce []byte) ([]byte, error) {
	if len(nonce) == 0 {
		return nil, ErrIllegalNonce
	}

	plaintext, err := key.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

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
func PublicKeyToPem(pub *rsa.PublicKey) (string, error) {
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

// MapToJwk transforms a Jwk in map structure to a Jwk Key. The map structure is a typical result from json deserialization
func MapToJwk(jwkAsMap map[string]interface{}) (jwk.Key, error) {
	set, err := MapsToJwkSet([]map[string]interface{}{jwkAsMap})
	if err != nil {
		return nil, err
	}
	return set.Keys[0], nil
}

func MapsToJwkSet(maps []map[string]interface{}) (*jwk.Set, error) {
	set := &jwk.Set{}
	var keys []interface{}
	for _, m := range maps {
		keys = append(keys, deepCopyMap(m))
	}
	root := map[string]interface{}{"keys": keys}
	if err := set.ExtractMap(root); err != nil {
		return set, err
	}
	return set, nil
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
	root := map[string]interface{}{}
	// unreachable err
	_ = key.PopulateMap(root)
	if root[jwk.X509CertChainKey] != nil {
		// Bug in JWK library: X.509 certificate chain isn't marshalled correctly
		// Reported: https://github.com/lestrrat-go/jwx/issues/139
		chain := root[jwk.X509CertChainKey].([]*x509.Certificate)
		root[jwk.X509CertChainKey] = marshalX509CertChain(chain)
	}
	return root, nil
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
	return GetX509ChainFromHeaders(key)
}

// GetX509ChainFromHeaders tries to retrieve the X.509 certificate chain ("x5c") from the JWK/JWS and parse it.
// If it doesn't contain the "x5c" header, nil is returned. If the header is present but it couldn't be parsed,
// an error is returned.
func GetX509ChainFromHeaders(headers jwkHeaderReader) ([]*x509.Certificate, error) {
	chainInterf, _ := headers.Get(jwk.X509CertChainKey)
	if chainInterf == nil {
		return nil, nil
	}
	// For JWKs we don't need to do unmarshalling
	chain, ok := chainInterf.([]*x509.Certificate)
	if ok {
		// No further parsing needed
		return chain, nil
	}
	// For the case of JWS the returned header is either a string slice
	return unmarshalX509CertChain(chainInterf.([]string))
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

func marshalX509CertChain(chain []*x509.Certificate) []string {
	encodedCerts := make([]string, len(chain))
	for idx, cert := range chain {
		encodedCerts[idx] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return encodedCerts
}

func serialNumber() (int64, error) {
	// TODO: Make this implementation safer. This one just hopes for enough entropy.
	n, err := rand.Int(rand.Reader, big.NewInt(time.Now().UnixNano()*2))
	if err != nil {
		return 0, err
	}
	return time.Now().UnixNano() ^ (*n).Int64(), nil
}

type jwkHeaderReader interface {
	Get(string) (interface{}, bool)
}
