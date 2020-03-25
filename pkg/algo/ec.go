package algo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"math/big"
)

func getECKeyTypes() []KeyType {
	return []KeyType{
		// NIST ECDSA-secp256r1
		ecKey{curve: elliptic.P256()},
	}
}

// Taken from crypto/ecdsa/ecdsa.go
type ecdsaSignature struct {
	R, S *big.Int
}

type ecSigningAlgorithm struct {
	jwa  string
	hash crypto.Hash
}

func (s ecSigningAlgorithm) Sign(dataToBeSigned []byte, key interface{}) ([]byte, error) {
	if !getECKeyTypes()[0].Matches(key) {
		return nil, UnsupportedKeyTypeError(key)
	}
	// Cast is safe since Matches() checked the type
	privKey := key.(*ecdsa.PrivateKey)
	return privKey.Sign(rand.Reader, doHash(s.hash, dataToBeSigned), s.hash)
}

func (s ecSigningAlgorithm) VerifySignature(data []byte, signature []byte, key interface{}) (bool, error) {
	if !getECKeyTypes()[0].Matches(key) {
		return false, UnsupportedKeyTypeError(key)
	}
	sig := ecdsaSignature{}
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil || sig.S == nil || sig.R == nil {
		return false, fmt.Errorf("invalid signature format: %w", err)
	}
	// Cast is safe since Matches() checked the type
	pubKey := key.(*ecdsa.PublicKey)
	return ecdsa.Verify(pubKey, doHash(s.hash, data), sig.R, sig.S), nil
}

func (s ecSigningAlgorithm) JWAIdentifier() string {
	return s.jwa
}

type ecKey struct {
	curve elliptic.Curve
}

func (e ecKey) SigningAlgorithm() SigningAlgorithm {
	return &ecSigningAlgorithm{jwa: jwa.ES256.String(), hash: crypto.SHA256}
}

func (e ecKey) MarshalPEM(key interface{}) (string, error) {
	pubK, ok := key.(*ecdsa.PublicKey)
	if ok {
		asn1data, err := x509.MarshalPKIXPublicKey(pubK)
		if err != nil {
			return "", err
		}
		return encodeASN1(asn1data, "EC PUBLIC KEY"), nil
	}
	privK, ok := key.(*ecdsa.PrivateKey)
	if ok {
		asn1data, err := x509.MarshalPKCS8PrivateKey(privK)
		if err != nil {
			return "", err
		}
		return encodeASN1(asn1data, "EC PRIVATE KEY"), nil
	}
	return "", UnsupportedKeyTypeError(key)
}

func (e ecKey) Matches(key interface{}) bool {
	pubK, ok := key.(*ecdsa.PublicKey)
	if ok {
		return pubK.Curve == e.curve
	}
	privK, ok := key.(*ecdsa.PrivateKey)
	return ok && privK.Curve == e.curve
}

func (e ecKey) Generate() (privKey interface{}, pubKey interface{}, err error) {
	key, err := ecdsa.GenerateKey(e.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key, &key.PublicKey, nil
}

func (e ecKey) Identifier() string {
	return fmt.Sprintf("%s-%s", "EC", e.curve.Params().Name)
}
