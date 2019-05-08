// types and interfaces used by all other packages
package types

import "crypto/rsa"

// --cryptobackend config flag
const ConfigBackend string = "cryptobackend"

// default setting for --cryptobackend "fs"
const ConfigBackendFs string = "fs"

// --fspath config flag
const ConfigFSPath string = "fspath"

// default setting for --fspath "./"
const ConfigFSPathDefault string = "./"

// type identifying the legalEntity responsible for the Patient/medical data
type LegalEntity struct{
	Uri string
}

// main interface for cryptographic functions. Main configuration is done via Viper
type Client interface {
	// Generate a new key pair for this LegalEntity.
	GenerateKeyPair(identifier LegalEntity) error

	// Decrypt a cipher text for a given LegalEntity. Uses the stored private key of the LegalEntity
	// Uses RSA assymetric encryption
	DecryptCipherTextFor(cipherText []byte, legalEntity LegalEntity) ([]byte, error)

	// Encrypt a piece of data for a legalEntity, can only be used if the legalEntity is also served through the current node, otherwise no keys are stored. In that case use the EncryptCipherTextWith function
	EncryptPlainTextFor(plaintext []byte, legalEntity LegalEntity) ([]byte, error)

	// Encrypt a piece of data with a PublicKey
	EncryptPlainTextWith(plaintext []byte, key *rsa.PublicKey) ([]byte, error)

	// Decrypt a piece of data that has been encrypted with a symmetric key which has been encrypted with a asymmetric key
	DecryptKeyAndCipherTextFor(cipherText DoubleEncryptedCipherText, legalEntity LegalEntity) ([]byte, error)

	// Encrypt a piece of data with the extra layer of a symmetric key. Returns cipherText and encrypted symmetric key with nonce
	EncryptKeyAndPlainTextFor(cipherText []byte, legalEntity LegalEntity) (DoubleEncryptedCipherText, error)

	// Encrypt a piece of data with the extra layer of a symmetric key. Returns cipherText and encrypted symmetric key
	EncryptKeyAndPlainTextWith(cipherText []byte, key *rsa.PublicKey) (DoubleEncryptedCipherText, error)
}

// Struct defining the encrypted data in CipherText, a encrypted symmetric key in CipherTextKey and the nonce needed for the AES_GCM decryption.
type DoubleEncryptedCipherText struct {
	CipherText []byte
	CipherTextKey []byte
	Nonce []byte
}

// Generic error
type Error struct {
	Msg string
}
// error interface
func (ce Error) Error() string {
	return ce.Msg
}