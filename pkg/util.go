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
	set := &jwk.Set{}
	root := map[string]interface{}{}
	root["keys"] = []interface{}{jwkAsMap}
	if err := set.ExtractMap(root); err != nil {
		return nil, err
	}
	return set.Keys[0], nil
}

// JwkToMap transforms a Jwk key to a map. Can be used for json serialization
func JwkToMap(jwk jwk.Key) (map[string]interface{}, error) {
	root := map[string]interface{}{}
	// unreachable err
	_ = jwk.PopulateMap(root)
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

func serialNumber() (int64, error) {
	// TODO: Make this implementation safer. This one just hopes for enough entropy.
	n, err := rand.Int(rand.Reader, big.NewInt(time.Now().UnixNano()*2))
	if err != nil {
		return 0, err
	}
	return time.Now().UnixNano() ^ (*n).Int64(), nil
}
