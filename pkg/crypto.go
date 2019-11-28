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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	"io"
	"strings"
	"sync"
)

// ErrInvalidKeySize is returned when the keySize for new keys is too short
var ErrInvalidKeySize = core.NewError("invalid keySize, needs to be at least 2048 bits", false)

// ErrMissingLegalEntityURI is returned when a required legal entity is missing
var ErrMissingLegalEntityURI = core.NewError("missing legalEntity URI", false)

// ErrMissingActor indicates the actor is missing
var ErrMissingActor = core.NewError("missing actor", false)

// ErrMissingSubject indicates the Subject is missing
var ErrMissingSubject = core.NewError("missing subject", false)

// ErrIllegalNonce indicates an incorrect nonce
var ErrIllegalNonce = core.NewError("illegal nonce given", false)

// ErrWrongPublicKey indicates a wrong public key format
var ErrWrongPublicKey = core.NewError("failed to decode PEM block containing public key, key is of the wrong type", false)

// ErrRsaPubKeyConversion indicates a public key could not be converted to an RSA public key
var ErrRsaPubKeyConversion = core.NewError("Unable to convert public key to RSA public key", false)

type CryptoConfig struct {
	Keysize int
	Storage string
	Fspath  string
}

// default implementation for CryptoInstance
type Crypto struct {
	Storage storage.Storage
	//keyCache map[string]rsa.PrivateKey
	Config     CryptoConfig
	configOnce sync.Once
	configDone bool
}

var instance *Crypto

var oneBackend sync.Once

func CryptoInstance() *Crypto {
	oneBackend.Do(func() {
		instance = &Crypto{
			Config: CryptoConfig{
				Keysize: types.ConfigKeySizeDefault,
			},
		}
	})
	return instance
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (client *Crypto) Configure() error {
	var err error

	client.configOnce.Do(func() {
		if client.Config.Keysize < 2048 {
			err = ErrInvalidKeySize
			return
		}

		client.Storage, err = client.newCryptoStorage()
		client.configDone = true
	})

	return err
}

// Helper function to create a new CryptoInstance. It checks the config (via Viper) for a --cryptobackend setting
// if none are given or this is set to 'fs', the filesystem backend is used.
func (client *Crypto) newCryptoStorage() (storage.Storage, error) {
	if client.Config.Storage == types.ConfigStorageFs || client.Config.Storage == "" {
		fspath := client.Config.Fspath
		if fspath == "" {
			fspath = types.ConfigFSPathDefault
		}

		return storage.NewFileSystemBackend(fspath)
	}

	return nil, errors.New("Only fs backend available for now")
}

// generate a new rsa keypair for the given legalEntity. The legalEntity uri is base64 encoded and used as filename
// for the key.
func (client *Crypto) GenerateKeyPairFor(legalEntity types.LegalEntity) error {
	var err error = nil

	if len(legalEntity.URI) == 0 {
		return ErrMissingLegalEntityURI
	}

	reader := rand.Reader

	key, err := rsa.GenerateKey(reader, client.Config.Keysize)

	if err != nil {
		return err
	}

	err = client.Storage.SavePrivateKey(legalEntity, key)

	//if err == nil {
	//	// also store key in cache
	//	client.keyCache[legalEntity.URI] = *key
	//}

	return err
}

// Main decryption function, first the symmetric key will be decrypted using the private key of the legal entity.
// The resulting symmetric key will then be used to decrypt the given cipherText.
func (client *Crypto) DecryptKeyAndCipherTextFor(cipherText types.DoubleEncryptedCipherText, legalEntity types.LegalEntity) ([]byte, error) {

	if len(cipherText.CipherTextKeys) != 1 {
		return nil, core.Errorf("unsupported count of CipherTextKeys: %d", false, len(cipherText.CipherTextKeys))
	}

	symmKey, err := client.decryptCipherTextFor(cipherText.CipherTextKeys[0], legalEntity)

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
func (client *Crypto) EncryptKeyAndPlainTextWith(plainText []byte, keys []string) (types.DoubleEncryptedCipherText, error) {
	cipherBytes, cipher, err := generateSymmetricKey()

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	cipherText, nonce, err := encryptWithSymmetricKey(plainText, cipher)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	var cipherTextKeys [][]byte

	for _, pemKey := range keys {
		pk, err := PemToPublicKey([]byte(pemKey))
		if err != nil {
			return types.DoubleEncryptedCipherText{}, err
		}

		encSymKey, err := client.encryptPlainTextWith(cipherBytes, pk)
		if err != nil {
			return types.DoubleEncryptedCipherText{}, err
		}
		cipherTextKeys = append(cipherTextKeys, encSymKey)
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

// ExternalIdFor creates an unique identifier which is repeatable. It uses the legalEntity private key as key.
// This is not for security but does generate the same unique identifier every time. It should only be used as unique identifier for consent records. Using the private key also ensure the BSN can not be deduced from the externalID.
// todo: check by others if this makes sense
func (client *Crypto) ExternalIdFor(subject string, actor string, entity types.LegalEntity) ([]byte, error) {
	if len(strings.TrimSpace(subject)) == 0 {
		return nil, ErrMissingSubject
	}

	if len(strings.TrimSpace(actor)) == 0 {
		return nil, ErrMissingActor
	}

	pk, err := client.Storage.GetPrivateKey(entity)
	if err != nil {
		return nil, err
	}

	// Create a new HMAC
	h := hmac.New(sha256.New, pk.D.Bytes())
	h.Write([]byte(subject))
	h.Write([]byte(actor))

	return h.Sum(nil), nil
}

// SignFor signs a piece of data for a legal entity. This requires the private key for the legal entity to be present.
// It is expected that the plain data is given. It uses the SHA256 hashing function
// todo: SHA_256?
func (client *Crypto) SignFor(data []byte, legalEntity types.LegalEntity) ([]byte, error) {
	// random
	rng := rand.Reader

	rsaPrivateKey, err := client.Storage.GetPrivateKey(legalEntity)
	hashedData := sha256.Sum256(data)

	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rng, rsaPrivateKey, crypto.SHA256, hashedData[:])

	if err != nil {
		return nil, err
	}

	return signature, err
}

// VerifyWith verfifies a signature of some data with a given PublicKeyInPEM. It uses the SHA256 hashing function.
func (client *Crypto) VerifyWith(data []byte, sig []byte, pemKey string) (bool, error) {
	key, err := PemToPublicKey([]byte(pemKey))

	if err != nil {
		return false, err
	}

	hashedData := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashedData[:], sig); err != nil {
		return false, err
	}

	return true, nil
}

// PublicKeyInPEM loads the key from storage and returns it as PEM encoded. Only supports RSA style keys
func (client *Crypto) PublicKeyInPEM(legalEntity types.LegalEntity) (string, error) {
	pubKey, err := client.Storage.GetPublicKey(legalEntity)

	if err != nil {
		return "", err
	}

	return PublicKeyToPem(pubKey)
}

// PublicKeyInJWK loads the key from storage and wraps it in a Key format. Supports RSA, ECDSA and Symmetric style keys
func (client *Crypto) PublicKeyInJWK(legalEntity types.LegalEntity) (jwk.Key, error) {
	pubKey, err := client.Storage.GetPublicKey(legalEntity)

	if err != nil {
		return nil, err
	}

	return jwk.New(pubKey)
}

// SignJwtFor creates a signed JWT given a legalEntity and map of claims
func (client *Crypto) SignJwtFor(claims map[string]interface{}, legalEntity types.LegalEntity) (string, error) {
	rsaPrivateKey, err := client.Storage.GetPrivateKey(legalEntity)

	if err != nil {
		return "", err
	}

	c := jwt.MapClaims{}
	for k, v := range claims {
		c[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	return token.SignedString(rsaPrivateKey)
}

// Decrypt a piece of data for the given legalEntity. It loads the private key from the storage and decrypts the cipherText.
// It returns an error if the given legalEntity does not have a private key.
func (client *Crypto) decryptCipherTextFor(cipherText []byte, legalEntity types.LegalEntity) ([]byte, error) {

	key, err := client.Storage.GetPrivateKey(legalEntity)

	if err != nil {
		return nil, err
	}

	plainText, err := decryptWithPrivateKey(cipherText, key)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Encrypt a piece of data for a legalEntity. Usually encryptPlainTextWith will be used with a public key of a different (unknown) legalEntity.
// It returns an error if the given legalEntity does not have a private key.
func (client *Crypto) encryptPlainTextFor(plaintext []byte, legalEntity types.LegalEntity) ([]byte, error) {

	publicKey, err := client.Storage.GetPublicKey(legalEntity)

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

	return nil, nil
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
