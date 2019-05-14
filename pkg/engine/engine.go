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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/golang/glog"
	"github.com/labstack/echo/v4"
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/backend"
	"github.com/nuts-foundation/nuts-crypto/pkg/generated"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	"net/http"
)

type CryptoEngine struct {
	backend backend.Backend
	//keyCache map[string]rsa.PrivateKey
	keySize int
}

// initiate file system client, loads config from Viper or returns error when config is incorrect
// it also creates the directories at the configured fspath
func NewCryptoEngine() *CryptoEngine {
	return &CryptoEngine{
		//keyCache: make(map[string]rsa.PrivateKey),
		keySize: types.ConfigKeySizeDefault,
	}
}

// Cmd gives the optional sub-command for the engine. An engine can only add one sub-command (multiple sub-sub-commands for the sub-command)
func (ce *CryptoEngine) Cmd() *cobra.Command {
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
			ce.GenerateKeyPairImpl(types.LegalEntity{URI: args[0]})
		},
	})

	return cmd
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (ce *CryptoEngine) Configure() error {
	var err error

	if viper.IsSet(types.ConfigKeySize) {
		keySize := viper.GetInt(types.ConfigKeySize)

		if keySize < 2048 {
			return types.Error{Msg: "invalid keySize, needs to be at least 2048 bits"}
		}
		ce.keySize = keySize
	}

	if ce.backend, err = backend.NewCryptoBackend(); err != nil {
		return err
	}

	return nil
}

// FlasSet returns all global configuration possibilities so they can be displayed through the help command
func (ce *CryptoEngine) FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	flags.String(types.ConfigBackend, types.ConfigBackendFs, "backend to use, 'fs' for file system (default)")
	flags.String(types.ConfigFSPath, types.ConfigFSPathDefault, "when file system is used as backend, this configures the path where keys are stored (default .)")
	flags.Int(types.ConfigKeySize, types.ConfigKeySizeDefault, "number of bits to use when creating new RSA keys")

	return flags
}

// Routes supported by CryptoEngine: POST /crypto
func (ce *CryptoEngine) Routes(router runtime.EchoRouter) {
	generated.RegisterHandlers(router, ce)
}

// Shutdown the CryptoEngine, NOP
func (ce *CryptoEngine) Shutdown() error {
	return nil
}

// Start the CryptoEngine, NOP
func (ce *CryptoEngine) Start() error {
	return nil
}

// GenerateKeyPair is the implementation of the REST service call POST /crypto/generate
func (ce *CryptoEngine) GenerateKeyPair(ctx echo.Context, params generated.GenerateKeyPairParams) error {
	if err := ce.GenerateKeyPairImpl(types.LegalEntity{URI: string(params.LegalEntityURI)}); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusCreated)
}

// Encrypt is the implementation of the REST service call POST /crypto/encrypt
func (ce *CryptoEngine) Encrypt(ctx echo.Context) error {
	buf, err := ioutil.ReadAll(ctx.Request().Body)
	if err != nil {
		glog.Error(err.Error())
		return err
	}

	var encryptRequest = &generated.EncryptRequest{}
	err = json.Unmarshal(buf, encryptRequest)

	if err != nil {
		glog.Error(err.Error())
		return err
	}

	if len(encryptRequest.LegalEntityURI) == 0 && len(encryptRequest.PublicKey) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing either legalEntityURI or publicKey in encryptRequest")
	}

	if len(encryptRequest.LegalEntityURI) != 0 && len(encryptRequest.PublicKey) != 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "both legalEntityURI and publicKey given in encryptRequest, choose one")
	}

	var dect types.DoubleEncryptedCipherText

	plainTextBytes, err := base64.StdEncoding.DecodeString(encryptRequest.PlainText)

	if err != nil {
		glog.Error(err.Error())
		return err
	}

	if len(encryptRequest.LegalEntityURI) != 0 {
		if err != nil {
			glog.Error(err.Error())
			return err
		}

		dect, err = ce.EncryptKeyAndPlainTextFor(plainTextBytes, types.LegalEntity{URI: string(encryptRequest.LegalEntityURI)})
	}

	if len(encryptRequest.PublicKey) != 0 {
		publicKey, err := bytesToPublicKey([]byte(encryptRequest.PublicKey))
		if err != nil {
			glog.Error(err.Error())
			return err
		}

		dect, err = ce.EncryptKeyAndPlainTextWith(plainTextBytes, publicKey)
	}

	if err != nil {
		glog.Error(err.Error())
		return err
	}

	return ctx.JSON(http.StatusOK, dectToEncryptResponse(dect))
}

func dectToEncryptResponse(dect types.DoubleEncryptedCipherText) generated.EncryptResponse {
	return generated.EncryptResponse{
		CipherText: base64.StdEncoding.EncodeToString(dect.CipherText),
		CipherTextKey: base64.StdEncoding.EncodeToString(dect.CipherTextKey),
		Nonce: base64.StdEncoding.EncodeToString(dect.Nonce),
	}
}

// Decrypt is the API handler function for decrypting a piece of data.
func (ce *CryptoEngine) Decrypt(ctx echo.Context) error {
	buf, err := ioutil.ReadAll(ctx.Request().Body)
	if err != nil {
		glog.Error(err.Error())
		return err
	}

	var decryptRequest = &generated.DecryptRequest{}
	err = json.Unmarshal(buf, decryptRequest)

	if err != nil {
		glog.Error(err.Error())
		return err
	}

	if len(decryptRequest.LegalEntityURI) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing legalEntityURI in decryptRequest")
	}


	dect, err := decryptRequestToDect(*decryptRequest)
	if err != nil {
		glog.Error(err.Error())
		return err
	}

	plainTextBytes, err := ce.DecryptKeyAndCipherTextFor(dect, types.LegalEntity{URI: string(decryptRequest.LegalEntityURI)})

	if err != nil {
		glog.Error(err.Error())
		return err
	}

	decryptResponse := generated.DecryptResponse{
		PlainText: base64.StdEncoding.EncodeToString(plainTextBytes),
	}

	return ctx.JSON(http.StatusOK, decryptResponse)
}

func decryptRequestToDect(gen generated.DecryptRequest) (types.DoubleEncryptedCipherText, error) {
	dect := types.DoubleEncryptedCipherText{}
	var err error

	dect.CipherText, err = base64.StdEncoding.DecodeString(gen.CipherText)
	if err != nil { return dect, err }
	dect.CipherTextKey, err = base64.StdEncoding.DecodeString(gen.CipherTextKey)
	if err != nil { return dect, err }
	dect.Nonce, err = base64.StdEncoding.DecodeString(gen.Nonce)
	if err != nil { return dect, err }

	return dect, nil
}

// ExternalId is the API handler function for generating a unique external identifier for a given identifier and legalEntity.
func (ce *CryptoEngine) ExternalId(ctx echo.Context) error {
	buf, err := ioutil.ReadAll(ctx.Request().Body)
	if err != nil {
		glog.Error(err.Error())
		return err
	}

	var request = &generated.ExternalIdRequest{}
	err = json.Unmarshal(buf, request)

	if err != nil {
		glog.Error(err.Error())
		return err
	}

	if len(request.LegalEntityURI) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing legalEntityURI in request")
	}
	if len(request.SubjectURI) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing subjectURI in request")
	}

	shaBytes, err := ce.ExternalIdFor([]byte(request.SubjectURI), types.LegalEntity{URI: string(request.LegalEntityURI)})
	if err != nil {
		glog.Error(err.Error())
		return err
	}

	sha := hex.EncodeToString(shaBytes)

	externalIdResponse := generated.ExternalIdResponse{
		ExternalId: sha,
	}

	return ctx.JSON(http.StatusOK, externalIdResponse)
}

// generate a new rsa keypair for the given legalEntity. The legalEntity uri is base64 encoded and used as filename
// for the key.
func (client *CryptoEngine) GenerateKeyPairImpl(legalEntity types.LegalEntity) error {
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

// Decrypt a piece of data for the given legalEntity. It loads the private key from the backend and decrypts the cipherText.
// It returns an error if the given legalEntity does not have a private key.
func (client *CryptoEngine) DecryptCipherTextFor(cipherText []byte, legalEntity types.LegalEntity) ([]byte, error) {

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
func (client *CryptoEngine) EncryptPlainTextFor(plaintext []byte, legalEntity types.LegalEntity) ([]byte, error) {

	publicKey, err := client.backend.GetPublicKey(legalEntity)

	if err != nil {
		return nil, err
	}

	return client.EncryptPlainTextWith(plaintext, publicKey)
}

// Encrypt a piece of data with the given public key
func (client *CryptoEngine) EncryptPlainTextWith(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {

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
func (client *CryptoEngine) DecryptKeyAndCipherTextFor(cipherText types.DoubleEncryptedCipherText, legalEntity types.LegalEntity) ([]byte, error) {

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
func (client *CryptoEngine) EncryptKeyAndPlainTextFor(plainText []byte, legalEntity types.LegalEntity) (types.DoubleEncryptedCipherText, error) {
	pubKey, err := client.backend.GetPublicKey(legalEntity)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	return client.EncryptKeyAndPlainTextWith(plainText, pubKey)
}

// Main encryption function, first the symmetric key is generated and used to encrypt the data.
// The resulting symmetric key will then be encrypted using the public key.
// CipherText, EncryptedKey and nonce are all returned. in the form of types.DoubleEncryptedCipherText
func (client *CryptoEngine) EncryptKeyAndPlainTextWith(plainText []byte, key *rsa.PublicKey) (types.DoubleEncryptedCipherText, error) {
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

// ExternalIdFor creates an unique identifier which is repeatable. It uses the legalEntity public key as key.
// This is not secure but does generate the same unique identifier everytime. It should only be used as unique identifier for consent records.
func (client *CryptoEngine) ExternalIdFor(data []byte, entity types.LegalEntity) ([]byte, error) {
	pk, err := client.backend.GetPublicKey(entity)
	if err != nil {
		return nil, err
	}

	// Create a new HMAC
	h := hmac.New(sha256.New, pk.N.Bytes())
	h.Write(data)

	return h.Sum(nil), nil
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