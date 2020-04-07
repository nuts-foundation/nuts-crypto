package algo

import (
	"fmt"
	"hash"
)

type KeyType interface {
	Identifier() string
	Generate() (privKey interface{}, pubKey interface{}, err error)
	Matches(key interface{}) bool
	MarshalPEM(key interface{}) (string, error)
	// SigningAlgorithm returns the recommended signing algorithm for this key type
	SigningAlgorithm() SigningAlgorithm
	// EncryptionAlgorithm returns the recommended encryption algorithm for this key type
	EncryptionAlgorithm() EncryptionAlgorithm
	CreateHMAC(privKey interface{}) (hash.Hash, error)
}

type SigningAlgorithm interface {
	// JWAIdentifier returns the JSON Web Algorithm equivalent for this signing algorithm which can be used to create
	// JSON Web Signatures (JWS) or JSON Web Tokens (JWT).
	JWAIdentifier() string
	// Sign signs the dataToBeSigned with the given key. The key should be a pointer to the private key.
	// If the key type is not supported by the algorithm, an error is returned.
	Sign(dataToBeSigned []byte, key interface{}) ([]byte, error)
	// VerifySignature verifies the given signature. The key should be a pointer to the public key.
	// If the key type is not supported by the algorithm, an error is returned.
	VerifySignature(data []byte, signature []byte, key interface{}) (bool, error)
}

type EncryptionAlgorithm interface {
	Encrypt(data []byte, key interface{}) ([]byte, error)
	Decrypt(data []byte, key interface{}) ([]byte, error)
}

func UnsupportedKeyTypeError(kt interface{}) error {
	str, ok := kt.(string)
	if !ok {
		str = fmt.Sprintf("%T", kt)
	}
	return fmt.Errorf("unsupported key type: %s", str)
}
