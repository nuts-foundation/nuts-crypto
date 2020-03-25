package algo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
)

func getRSAKeyFamily() keyFamily {
	keyTypes := []KeyType{
		rsaKey{bits: 3072},
		rsaKey{bits: 4096},
	}
	sigAlgs := []SigningAlgorithm{
		signingAlgorithm{jwa.PS256.String()},
		signingAlgorithm{jwa.PS384.String()},
		signingAlgorithm{jwa.PS512.String()},
	}
	return keyFamily{
		name:          "RSA",
		recommendedKT: keyTypes,
		// 2048 bits RSA keys are supported, but it is advised to use longer key lengths (Dutch NCSC as of March 2020)
		supportedKT:   append(keyTypes, rsaKey{bits: 2048}),
		recommendedSA: append(sigAlgs),
		// RSA signature with SHA-256 digest is supported, but it is advised to switch to RSA-PSS (Dutch NCSC as of March 2020)
		supportedSA: append(sigAlgs, signingAlgorithm{jwa.RS256.String()}),
	}
}

type rsaKey struct {
	bits int
}

func (e rsaKey) MarshalPEM(key interface{}) (string, error) {
	pubK, ok := key.(*rsa.PublicKey)
	if ok {
		asn1data, err := x509.MarshalPKIXPublicKey(pubK)
		if err != nil {
			return "", err
		}
		return encodeASN1(asn1data, "RSA PUBLIC KEY"), nil
	}
	privK, ok := key.(*rsa.PrivateKey)
	if ok {
		asn1data, err := x509.MarshalPKCS8PrivateKey(privK)
		if err != nil {
			return "", err
		}
		return encodeASN1(asn1data, "RSA PRIVATE KEY"), nil
	}
	return "", UnsupportedKeyTypeError(key)
}

func (e rsaKey) Matches(key interface{}) bool {
	pubK, ok := key.(*rsa.PublicKey)
	if ok {
		return pubK.Size()*8 == e.bits
	}
	privK, ok := key.(*rsa.PrivateKey)
	return privK.Size()*8 == e.bits
}

func (e rsaKey) Generate() (privKey interface{}, pubKey interface{}, err error) {
	key, err := rsa.GenerateKey(rand.Reader, e.bits)
	if err != nil {
		return nil, nil, err
	}
	return key, &key.PublicKey, nil
}

func (e rsaKey) Identifier() string {
	return fmt.Sprintf("%s-%d", "RSA", e.bits)
}
