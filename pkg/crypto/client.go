/*
 * Nuts crypto
 * Copyright (C) 2019 Nuts community
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

// File system backed crypto client
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/backend"
	"io"
)

type cryptoClient struct {
	backend backend.Backend
	keyCache map[string]rsa.PrivateKey
}

// initiate file system client, loads config from Viper or returns error when config is incorrect
// it also creates the directories at the configured fspath
func NewCryptoClient() (types.Client, error) {
	backend, err := backend.NewCryptoBackend()

	if err != nil {
		return nil ,err
	}

	return &cryptoClient{
		backend: backend,
		keyCache: make(map[string]rsa.PrivateKey),
	}, nil
}

// generate a new rsa keypair for the given legalEntity. The legalEntity uri is base64 encoded and used as filename
// for the key. The generated key is also stored in a in-memory cache
func (client *cryptoClient) GenerateKeyPair(legalEntity types.LegalEntity) error {
	var err error = nil

	reader := rand.Reader

	// todo: make config
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)

	if err != nil {
		return err
	}

	err = client.backend.SavePrivateKey(legalEntity, key)

	if err == nil {
		// also store key in cache
		client.keyCache[legalEntity.Uri] = *key
	}

	return err
}

// Decrypt a piece of data for the given legalEntity. It loads the private key from the backend and decrypts the cipherText.
// It returns an error if the given legalEntity does not have a private key.
func (client *cryptoClient) DecryptCipherTextFor(cipherText []byte, legalEntity types.LegalEntity) ([]byte, error) {

	key, err := client.backend.GetPrivateKey(legalEntity)

	if err != nil {
		return nil, err
	}

	plainText, err := decryptWithPrivateKey(cipherText, key)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Encrypt a piece of data for a legalEntity. Usually EncryptPlainTextWith will be used with a public key of a different (unknown) legalEntity.
// It returns an error if the given legalEntity does not have a private key.
func (client *cryptoClient) EncryptPlainTextFor(plaintext []byte, legalEntity types.LegalEntity) ([]byte, error) {

	publicKey, err := client.backend.GetPublicKey(legalEntity)

	if err != nil {
		return nil, err
	}

	return client.EncryptPlainTextWith(plaintext, publicKey)
}

// Encrypt a piece of data with the given public key
func (client *cryptoClient) EncryptPlainTextWith(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {

	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, key, plaintext, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil


	return nil, nil
}

// Main decryption function, first the symmetric key will be decrypted using the private key of the legal entity.
// The resulting symmetric key will then be used to decrypt the given cipherText
func (client *cryptoClient) DecryptKeyAndCipherTextFor(cipherText types.DoubleEncryptedCipherText, legalEntity types.LegalEntity) ([]byte, error) {

	symmKey, err := client.DecryptCipherTextFor(cipherText.CipherTextKey, legalEntity)

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

// Main encryption function, first the symmetric key is generated and used to encrypt the data.
// The resulting symmetric key will then be encrypted using the public key from the legal entity.
// CipherText, EncryptedKey and nonce are all returned. in the form of types.DoubleEncryptedCipherText
func (client *cryptoClient) EncryptKeyAndPlainTextFor(plainText []byte, legalEntity types.LegalEntity) (types.DoubleEncryptedCipherText, error) {
	pubKey, err := client.backend.GetPublicKey(legalEntity)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	return client.EncryptKeyAndPlainTextWith(plainText, pubKey)
}

// Main encryption function, first the symmetric key is generated and used to encrypt the data.
// The resulting symmetric key will then be encrypted using the public key.
// CipherText, EncryptedKey and nonce are all returned. in the form of types.DoubleEncryptedCipherText
func (client *cryptoClient) EncryptKeyAndPlainTextWith(plainText []byte, key *rsa.PublicKey) (types.DoubleEncryptedCipherText, error) {
	// create new symmetric key
	symkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, symkey); err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	block, err := aes.NewCipher(symkey)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	// encrypt plainText with this symmetric key
	cipherText, nonce, err := encryptWithSymmetricKey(plainText, aesgcm)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	encryptedKey, err := client.EncryptPlainTextWith(symkey, key)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	return types.DoubleEncryptedCipherText{CipherText: cipherText, CipherTextKey: encryptedKey, Nonce: nonce}, err
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

	plaintext, err := key.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func encryptWithSymmetricKey(plainText []byte, key cipher.AEAD) ([]byte, []byte, error) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	cipherText := key.Seal(nil, nonce, plainText, nil)

	return cipherText, nonce, nil
}
