package algo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"math/big"
)

func getECKeyFamily() keyFamily {
	keyTypes := []KeyType{
		// NIST ECDSA-secp256r1
		ecKey{curve: elliptic.P256()},
		// NIST ECDSA-secp384r1
		ecKey{curve: elliptic.P384()},
	}
	sigAlgs := []SigningAlgorithm{
		signingAlgorithm{jwa.ES256.String()},
		signingAlgorithm{jwa.ES384.String()},
	}
	return keyFamily{
		name:          "EC",
		recommendedKT: keyTypes,
		supportedKT:   keyTypes,
		recommendedSA: sigAlgs,
		supportedSA:   sigAlgs,
	}
}

func hashAndSignEC(key interface{}, dataToBeSigned []byte, hash crypto.Hash) ([]byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key should be *ecdsa.PrivateKey")
	}
	digest := hash.New()
	digest.Write(dataToBeSigned)
	calculatedHash := digest.Sum(nil)
	return ecKey.Sign(rand.Reader, calculatedHash, nil)
}

type ecdsaSignature struct {
	R, S *big.Int
}

type ecKey struct {
	curve elliptic.Curve
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
