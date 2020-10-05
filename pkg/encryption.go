/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"io"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
)

// The encryption functions are used for the consent record encryption. This is no longer needed when
// consent records are exchanged directly.

// ErrMissingActor indicates the actor is missing
var ErrMissingActor = core.NewError("missing actor", false)

// ErrMissingSubject indicates the Subject is missing
var ErrMissingSubject = core.NewError("missing subject", false)

// ErrIllegalNonce indicates an incorrect nonce
var ErrIllegalNonce = core.NewError("illegal nonce given", false)

// Main decryption function, first the symmetric key will be decrypted using the private key of the legal entity.
// The resulting symmetric key will then be used to decrypt the given cipherText.
func (client *Crypto) DecryptKeyAndCipherText(cipherText types.DoubleEncryptedCipherText, key types.KeyIdentifier) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidKeyIdentifier
	}
	if len(cipherText.CipherTextKeys) != 1 {
		return nil, core.Errorf("unsupported count of CipherTextKeys: %d", false, len(cipherText.CipherTextKeys))
	}

	symmKey, err := client.decryptCipherTextFor(cipherText.CipherTextKeys[0], key)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(symmKey)

	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	plaintext, err := decryptWithSymmetricKey(cipherText.CipherText, aesgcm, cipherText.Nonce)

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptKeyAndPlainTextFor encrypts a piece of data for the given public key
func (client *Crypto) EncryptKeyAndPlainText(plainText []byte, keys []jwk.Key) (types.DoubleEncryptedCipherText, error) {
	cipherBytes, cipher, err := generateSymmetricKey()

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	cipherText, nonce, err := encryptWithSymmetricKey(plainText, cipher)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	var cipherTextKeys [][]byte

	for _, jwk := range keys {
		pk, err := jwk.Materialize()
		if err != nil {
			return types.DoubleEncryptedCipherText{}, err
		}

		// todo support EC
		if rsaPk, ok := pk.(*rsa.PublicKey); ok {
			encSymKey, err := client.encryptPlainTextWith(cipherBytes, rsaPk)
			if err != nil {
				return types.DoubleEncryptedCipherText{}, err
			}
			cipherTextKeys = append(cipherTextKeys, encSymKey)
		} else {
			return types.DoubleEncryptedCipherText{}, ErrInvalidAlgorithm
		}
	}

	return types.DoubleEncryptedCipherText{
		Nonce:          nonce,
		CipherText:     cipherText,
		CipherTextKeys: cipherTextKeys,
	}, nil
}

func encryptWithSymmetricKey(plainText []byte, key cipher.AEAD) (cipherText []byte, nonce []byte, error error) {
	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	cipherText = key.Seal(nil, nonce, plainText, nil)

	return cipherText, nonce, nil
}

func generateSymmetricKey() ([]byte, cipher.AEAD, error) {
	symkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, symkey); err != nil {
		return nil, nil, err
	}

	aead, err := symmetricKeyToBlockCipher(symkey)

	return symkey, aead, err
}

func symmetricKeyToBlockCipher(ciph []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(ciph)

	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// CalculateExternalId creates an unique identifier which is repeatable. It uses the legalEntity private key as key.
// This is not for security but does generate the same unique identifier every time. It should only be used as unique identifier for consent records. Using the private key also ensure the BSN can not be deduced from the externalID.
func (client *Crypto) CalculateExternalId(subject string, actor string, key types.KeyIdentifier) ([]byte, error) {
	if len(strings.TrimSpace(subject)) == 0 {
		return nil, ErrMissingSubject
	}

	if len(strings.TrimSpace(actor)) == 0 {
		return nil, ErrMissingActor
	}

	pk, err := client.Storage.GetPrivateKey(key)
	if err != nil {
		return nil, err
	}

	// Create a new HMAC
	h := hmac.New(sha256.New, pk.D.Bytes())
	h.Write([]byte(subject))
	h.Write([]byte(actor))

	return h.Sum(nil), nil
}

// Decrypt a piece of data for the given legalEntity. It loads the private key from the storage and decrypts the cipherText.
// It returns an error if the given legalEntity does not have a private key.
func (client *Crypto) decryptCipherTextFor(cipherText []byte, key types.KeyIdentifier) ([]byte, error) {

	privateKey, err := client.Storage.GetPrivateKey(key)

	if err != nil {
		return nil, err
	}

	plainText, err := decryptWithPrivateKey(cipherText, privateKey)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Encrypt a piece of data for a legalEntity. Usually encryptPlainTextWith will be used with a public key of a different (unknown) legalEntity.
// It returns an error if the given legalEntity does not have a private key.
func (client *Crypto) encryptPlainTextFor(plaintext []byte, key types.KeyIdentifier) ([]byte, error) {

	publicKey, err := client.Storage.GetPublicKey(key)

	if err != nil {
		return nil, err
	}

	return client.encryptPlainTextWith(plaintext, publicKey)
}

// Encrypt a piece of data with the given public key
func (client *Crypto) encryptPlainTextWith(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {

	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, key, plaintext, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

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
