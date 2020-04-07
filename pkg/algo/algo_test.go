package algo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/stretchr/testify/assert"
	"reflect"
	"strings"
	"testing"
)

const supportedKeyTypes = `
EC-P-256
RSA-3072
RSA-4096
RSA-2048
`

func TestSupportedKeyTypes(t *testing.T) {
	var actual = ""
	for _, kt := range SupportedKeyTypes() {
		actual += kt.Identifier() + "\n"
	}
	actual = strings.TrimSpace(actual)
	assert.Equal(t, actual, strings.TrimSpace(supportedKeyTypes))
}

func testKeyType(t *testing.T, keyType KeyType) {
	t.Run(keyType.Identifier(), func(t *testing.T) {
		println("  Generating key...")
		privKey, pubKey, err := keyType.Generate()
		assert.Equal(t, reflect.Ptr, reflect.TypeOf(privKey).Kind(), "generated private key is not a pointer")
		assert.Equal(t, reflect.Ptr, reflect.TypeOf(pubKey).Kind(), "generated public key is not a pointer")
		if !assert.NoError(t, err) {
			return
		}
		t.Run("matching", func(t *testing.T) {
			assert.True(t, keyType.Matches(privKey), "private key should match")
			assert.True(t, keyType.Matches(pubKey), "public key should match")
		})
		t.Run("marshalling private key", func(t *testing.T) {
			err := testKeyMarshalling(t, keyType, privKey)
			assert.NoError(t, err)
		})
		t.Run("marshalling public key", func(t *testing.T) {
			err := testKeyMarshalling(t, keyType, pubKey)
			assert.NoError(t, err)
		})
		t.Run("signing", func(t *testing.T) {
			dataToBeSigned := []byte{1, 2, 3}
			signature, err := keyType.SigningAlgorithm().Sign(dataToBeSigned, privKey)
			t.Run("ok", func(t *testing.T) {
				assert.NoError(t, err)
				signatureOK, err := keyType.SigningAlgorithm().VerifySignature(dataToBeSigned, signature, pubKey)
				assert.NoError(t, err)
				assert.True(t, signatureOK, "signature should be OK")
			})
			t.Run("nok (incorrect public key)", func(t *testing.T) {
				_, altPubKey, _ := keyType.Generate()
				signatureNOK, err := keyType.SigningAlgorithm().VerifySignature(dataToBeSigned, signature, altPubKey)
				assert.NoError(t, err)
				assert.False(t, signatureNOK, "signature should NOT be OK")
			})
		})
		t.Run("encryption", func(t *testing.T) {
			t.Run("ok", func(t *testing.T) {
				plaintext := []byte{1, 2, 3}
				cipherText, err := keyType.EncryptionAlgorithm().Encrypt(plaintext, pubKey)
				if !assert.NoError(t, err) {
					return
				}
				result, err := keyType.EncryptionAlgorithm().Decrypt(cipherText, privKey)
				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, plaintext, result)
			})
			t.Run("nok (incorrect cipher text)", func(t *testing.T) {
				result, err := keyType.EncryptionAlgorithm().Decrypt([]byte{3, 2, 1}, privKey)
				assert.Error(t, err)
				assert.Nil(t, result)
			})
		})
	})
}

func testKeyMarshalling(t *testing.T, keyType KeyType, key interface{}) error {
	keyPem, err := keyType.MarshalPEM(key)
	if !assert.NoError(t, err) {
		return err
	}
	unmarshalledKey, err := UnmarshalPEM(keyPem)
	if !assert.NoError(t, err) {
		return err
	}
	if !assert.Equal(t, key, unmarshalledKey) {
		return errors.New("not equal")
	}
	return nil
}

func TestGetKeyTypeFromKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		kt, err := GetKeyTypeFromKey(key)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, kt)
	})
	t.Run("error", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 1024)
		kt, err := GetKeyTypeFromKey(key)
		assert.EqualError(t, err, "unsupported key type: *rsa.PrivateKey")
		assert.Nil(t, kt)
	})
}

func TestGetKeyTypeFromIdentifier(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		kt, err := GetKeyTypeFromIdentifier("EC-P-256")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, kt)
	})
	t.Run("error", func(t *testing.T) {
		kt, err := GetKeyTypeFromIdentifier("abc")
		assert.EqualError(t, err, "unsupported key type: abc")
		assert.Nil(t, kt)
	})
}
