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
EC-P-384
RSA-3072
RSA-4096
RSA-2048
`
const recommendedKeyTypes = `
EC-P-256
EC-P-384
RSA-3072
RSA-4096
`
const supportedSigAlgs = `
ES256
ES384
PS256
PS384
PS512
RS256
`

const recommendedSigAlgs = `
ES256
ES384
PS256
PS384
PS512
`

func TestKeys(t *testing.T) {

}

func TestSupportedKeyTypes(t *testing.T) {
	var actual = ""
	for _, kt := range SupportedKeyTypes() {
		actual += kt.Identifier() + "\n"
	}
	actual = strings.TrimSpace(actual)
	assert.Equal(t, actual, strings.TrimSpace(supportedKeyTypes))
}

func TestRecommendedKeyTypes(t *testing.T) {
	var actual = ""
	for _, kt := range RecommendedKeyTypes() {
		actual += kt.Identifier() + "\n"
	}
	actual = strings.TrimSpace(actual)
	assert.Equal(t, actual, strings.TrimSpace(recommendedKeyTypes))
}

func TestSupportedSigningAlgorithms(t *testing.T) {
	var actual = ""
	for _, kt := range SupportedSigningAlgorithms() {
		actual += kt.JWAIdentifier() + "\n"
	}
	actual = strings.TrimSpace(actual)
	assert.Equal(t, actual, strings.TrimSpace(supportedSigAlgs))
}

func TestRecommendedSigningAlgorithms(t *testing.T) {
	var actual = ""
	for _, kt := range RecommendedSigningAlgorithms() {
		actual += kt.JWAIdentifier() + "\n"
	}
	actual = strings.TrimSpace(actual)
	assert.Equal(t, actual, strings.TrimSpace(recommendedSigAlgs))
}

func Test_keyFamily_IsKeySupported(t *testing.T) {
	fam := getECKeyFamily()
	t.Run("ok", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.True(t, fam.IsKeySupported(key))
	})
	t.Run("not supported", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 1024)
		assert.False(t, fam.IsKeySupported(key))
	})

}

func testKeyType(t *testing.T, keyType KeyType, family KeyFamily) {
	println("Testing key type:", keyType.Identifier())
	println("  Generating key...")
	privKey, pubKey, err := keyType.Generate()
	assert.Equal(t, reflect.Ptr, reflect.TypeOf(privKey).Kind(), "generated private key is not a pointer")
	assert.Equal(t, reflect.Ptr, reflect.TypeOf(pubKey).Kind(), "generated public key is not a pointer")
	if !assert.NoError(t, err) {
		return
	}
	println("  Test matching")
	assert.True(t, keyType.Matches(privKey), "private key should match")
	assert.True(t, keyType.Matches(pubKey), "public key should match")
	println("  Marshalling private key")
	testKeyMarshalling(t, keyType, privKey)
	if !assert.NoError(t, err) {
		return
	}
	println("  Marshalling public key")
	testKeyMarshalling(t, keyType, pubKey)
	if !assert.NoError(t, err) {
		return
	}
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

func TestRecommendedSigningAlgorithm(t *testing.T) {
	t.Run("ok - EC key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		alg, err := RecommendedSigningAlgorithm(key)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "ES256", alg.JWAIdentifier())
	})
	t.Run("not found", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 1024)
		alg, err := RecommendedSigningAlgorithm(key)
		assert.Nil(t, alg)
		assert.EqualError(t, err, "no supported signing algorithms for key: *rsa.PrivateKey")
	})
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
