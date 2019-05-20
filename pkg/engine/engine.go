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

package engine

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
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/backend"
	"github.com/nuts-foundation/nuts-crypto/pkg/generated"
	"github.com/nuts-foundation/nuts-go/pkg"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"sync"
)

// CryptoEngine contains both the CryptoClient interface as the generic Nuts Engine interface
type CryptoEngine interface {
	CryptoClient
	pkg.Engine
}

// default implementation of a CryptoEngine
type DefaultCryptoEngine struct {
	backend backend.Backend
	//keyCache map[string]rsa.PrivateKey
	keySize int
}

var instance *DefaultCryptoEngine
var oneEngine sync.Once

// NewCryptoEngine initiates the engine with configured parameters (through viper). In this version it always uses a disk backend.
func NewCryptoEngine() *DefaultCryptoEngine {
	oneEngine.Do(func() {
		instance = &DefaultCryptoEngine{
			//keyCache: make(map[string]rsa.PrivateKey),
			keySize: types.ConfigKeySizeDefault,
		}
	})
	return instance
}

// Cmd gives the optional sub-command for the engine. An engine can only add one sub-command (multiple sub-sub-commands for the sub-command)
func (ce *DefaultCryptoEngine) Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "crypto commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "generateKeyPair [legalEntityURI]",
		Short: "generate a new keyPair for a legalEntity",

		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return types.Error{Msg: "requires a URI argument"}
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cc := NewCryptoClient()
			cc.GenerateKeyPairFor(types.LegalEntity{URI: args[0]})
		},
	})

	return cmd
}

var configOnce sync.Once
var ConfigDone bool

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (ce *DefaultCryptoEngine) Configure() error {
	var err error

	configOnce.Do(func() {
		if viper.IsSet(types.ConfigKeySize) {
			keySize := viper.GetInt(types.ConfigKeySize)

			if keySize < 2048 {
				err = types.Error{Msg: "invalid keySize, needs to be at least 2048 bits"}
				return
			}
			ce.keySize = keySize
		}

		ce.backend, err = backend.NewCryptoBackend()
		ConfigDone = true
	})

	return err
}

// FlasSet returns all global configuration possibilities so they can be displayed through the help command
func (ce *DefaultCryptoEngine) FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	flags.String(types.ConfigBackend, types.ConfigBackendFs, "backend to use, 'fs' for file system (default)")
	flags.String(types.ConfigFSPath, types.ConfigFSPathDefault, "when file system is used as backend, this configures the path where keys are stored (default .)")
	flags.Int(types.ConfigKeySize, types.ConfigKeySizeDefault, "number of bits to use when creating new RSA keys")

	return flags
}

// Routes supported by DefaultCryptoEngine: POST /crypto
func (ce *DefaultCryptoEngine) Routes(router runtime.EchoRouter) {
	generated.RegisterHandlers(router, ce)
}

// Shutdown the DefaultCryptoEngine, NOP
func (ce *DefaultCryptoEngine) Shutdown() error {
	return nil
}

// Start the DefaultCryptoEngine, NOP
func (ce *DefaultCryptoEngine) Start() error {
	return nil
}

// generate a new rsa keypair for the given legalEntity. The legalEntity uri is base64 encoded and used as filename
// for the key.
func (client *DefaultCryptoEngine) GenerateKeyPairFor(legalEntity types.LegalEntity) error {
	var err error = nil

	reader := rand.Reader

	key, err := rsa.GenerateKey(reader, client.keySize)

	if err != nil {
		return err
	}

	err = client.backend.SavePrivateKey(legalEntity, key)

	//if err == nil {
	//	// also store key in cache
	//	client.keyCache[legalEntity.URI] = *key
	//}

	return err
}

// Main decryption function, first the symmetric key will be decrypted using the private key of the legal entity.
// The resulting symmetric key will then be used to decrypt the given cipherText
func (client *DefaultCryptoEngine) DecryptKeyAndCipherTextFor(cipherText types.DoubleEncryptedCipherText, legalEntity types.LegalEntity) ([]byte, error) {

	symmKey, err := client.decryptCipherTextFor(cipherText.CipherTextKey, legalEntity)

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
func (client *DefaultCryptoEngine) EncryptKeyAndPlainTextFor(plainText []byte, legalEntity types.LegalEntity) (types.DoubleEncryptedCipherText, error) {
	pubKey, err := client.backend.GetPublicKey(legalEntity)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	return client.EncryptKeyAndPlainTextWith(plainText, pubKey)
}

// Main encryption function, first the symmetric key is generated and used to encrypt the data.
// The resulting symmetric key will then be encrypted using the public key.
// CipherText, EncryptedKey and nonce are all returned. in the form of types.DoubleEncryptedCipherText
func (client *DefaultCryptoEngine) EncryptKeyAndPlainTextWith(plainText []byte, key *rsa.PublicKey) (types.DoubleEncryptedCipherText, error) {
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

	encryptedKey, err := client.encryptPlainTextWith(symkey, key)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	return types.DoubleEncryptedCipherText{CipherText: cipherText, CipherTextKey: encryptedKey, Nonce: nonce}, err
}

// ExternalIdFor creates an unique identifier which is repeatable. It uses the legalEntity private key as key.
// This is not for security but does generate the same unique identifier every time. It should only be used as unique identifier for consent records. Using the private key also ensure the BSN can not be deduced from the externalID.
// todo: check by others if this makes sense
func (client *DefaultCryptoEngine) ExternalIdFor(data []byte, entity types.LegalEntity) ([]byte, error) {
	pk, err := client.backend.GetPrivateKey(entity)
	if err != nil {
		return nil, err
	}

	// Create a new HMAC
	h := hmac.New(sha256.New, pk.D.Bytes())
	h.Write(data)

	return h.Sum(nil), nil
}

// SignFor signs a piece of data for a legal entity. This requires the private key for the legal entity to be present.
// It is expected that the plain data is given. It uses the SHA512 hashing function
// todo: SHA_512?
func (client *DefaultCryptoEngine) SignFor(data []byte, legalEntity types.LegalEntity) ([]byte, error) {
	// random
	rng := rand.Reader

	rsaPrivateKey, err := client.backend.GetPrivateKey(legalEntity)
	hashedData := sha512.Sum512(data)

	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rng, rsaPrivateKey, crypto.SHA512, hashedData[:])

	if err != nil {
		return nil, err
	}

	return signature, err
}

// VerifyWith verfifies a signature of some data with a given PublicKey. It uses the SHA512 hashing function.
func (client *DefaultCryptoEngine) VerifyWith(data []byte, sig []byte, key *rsa.PublicKey) (bool, error) {
	hashedData := sha512.Sum512(data)
	if err:= rsa.VerifyPKCS1v15(key, crypto.SHA512, hashedData[:], sig); err != nil {
		return false, err
	}

	return true, nil
}

// Decrypt a piece of data for the given legalEntity. It loads the private key from the backend and decrypts the cipherText.
// It returns an error if the given legalEntity does not have a private key.
func (client *DefaultCryptoEngine) decryptCipherTextFor(cipherText []byte, legalEntity types.LegalEntity) ([]byte, error) {

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

// Encrypt a piece of data for a legalEntity. Usually encryptPlainTextWith will be used with a public key of a different (unknown) legalEntity.
// It returns an error if the given legalEntity does not have a private key.
func (client *DefaultCryptoEngine) encryptPlainTextFor(plaintext []byte, legalEntity types.LegalEntity) ([]byte, error) {

	publicKey, err := client.backend.GetPublicKey(legalEntity)

	if err != nil {
		return nil, err
	}

	return client.encryptPlainTextWith(plaintext, publicKey)
}

// Encrypt a piece of data with the given public key
func (client *DefaultCryptoEngine) encryptPlainTextWith(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {

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

// shared function to convert bytes to a RSA private key
func bytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	b := block.Bytes
	key, err := x509.ParsePKCS1PublicKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}
