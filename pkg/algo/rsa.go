package algo

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"hash"
)

func getRSAKeyTypes() []KeyType {
	return []KeyType{
		rsaKey{bits: 3072},
		rsaKey{bits: 4096},
		// 2048 bits RSA keys are supported, but it is advised to use longer key lengths (Dutch NCSC as of March 2020)
		rsaKey{bits: 2048},
	}
}

type rsaKey struct {
	bits int
}

func (e rsaKey) EncryptionAlgorithm() EncryptionAlgorithm {
	return rsaOAEPEncryptionAlgorithm{}
}

func (e rsaKey) SigningAlgorithm() SigningAlgorithm {
	return rsaSigningAlgorithm{jwa: jwa.RS256.String(), hash: crypto.SHA256}
}

func (e rsaKey) CreateHMAC(privKey interface{}) (hash.Hash, error) {
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, UnsupportedKeyTypeError(privKey)
	}
	return hmac.New(sha256.New, rsaKey.D.Bytes()), nil
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

type rsaSigningAlgorithm struct {
	jwa  string
	hash crypto.Hash
}

func (s rsaSigningAlgorithm) JWAIdentifier() string {
	return s.jwa
}

func (s rsaSigningAlgorithm) Sign(dataToBeSigned []byte, key interface{}) ([]byte, error) {
	if !isSupportedRSAKey(key) {
		return nil, UnsupportedKeyTypeError(key)
	}
	// Cast is safe since Matches() checked the type
	privKey := key.(*rsa.PrivateKey)
	return privKey.Sign(rand.Reader, doHash(s.hash, dataToBeSigned), s.hash)
}

func (s rsaSigningAlgorithm) VerifySignature(data []byte, signature []byte, key interface{}) (bool, error) {
	if !isSupportedRSAKey(key) {
		return false, UnsupportedKeyTypeError(key)
	}
	// Cast is safe since Matches() checked the type
	pubKey := key.(*rsa.PublicKey)
	err := rsa.VerifyPKCS1v15(pubKey, s.hash, doHash(s.hash, data), signature)
	if err == nil {
		return true, nil
	}
	var resultingErr error
	if !errors.Is(err, rsa.ErrVerification) {
		resultingErr = err
	}
	return err == nil, resultingErr
}

func isSupportedRSAKey(key interface{}) bool {
	for _, kt := range getRSAKeyTypes() {
		if kt.Matches(key) {
			return true
		}
	}
	return false
}

type rsaOAEPEncryptionAlgorithm struct {

}

func (r rsaOAEPEncryptionAlgorithm) Encrypt(data []byte, key interface{}) ([]byte, error) {
	if !isSupportedRSAKey(key) {
		return nil, UnsupportedKeyTypeError(key)
	}
	// Cast is safe since Matches() checked the type
	pubKey := key.(*rsa.PublicKey)
	hash := sha512.New()
	cipherText, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, data, nil)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func (r rsaOAEPEncryptionAlgorithm) Decrypt(data []byte, key interface{}) ([]byte, error) {
	if !isSupportedRSAKey(key) {
		return nil, UnsupportedKeyTypeError(key)
	}
	// Cast is safe since Matches() checked the type
	privKey := key.(*rsa.PrivateKey)
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
