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

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/nuts-foundation/nuts-go-test/io"
	"github.com/spf13/cobra"

	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	mock2 "github.com/nuts-foundation/nuts-crypto/test/mock"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-go-core/mock"
	"github.com/stretchr/testify/assert"
)

var key = types.KeyForEntity(types.LegalEntity{URI: "test"})

type pubKeyMatcher struct {
}

func (p pubKeyMatcher) Matches(x interface{}) bool {
	s := x.(string)

	return strings.Contains(s, "-----BEGIN PUBLIC KEY-----")
}

func (p pubKeyMatcher) String() string {
	return "Public Key Matcher"
}

type jwkMatcher struct {
}

func (p jwkMatcher) Matches(x interface{}) bool {
	key := x.(jwk.Key)

	return key.KeyType() == jwa.RSA
}

func (p jwkMatcher) String() string {
	return "JWK Matcher"
}

func TestApiWrapper_GenerateVendorCACSR(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		os.Setenv("NUTS_IDENTITY", "urn:oid:1.3.6.1.4.1.54851.4:4")
		defer os.Unsetenv("NUTS_IDENTITY")
		core.NutsConfig().Load(&cobra.Command{})

		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Blob(http.StatusOK, "application/x-pem-file", gomock.Any())

		se.GenerateVendorCACSR(echo, GenerateVendorCACSRParams{Name: "foo"})
	})
	t.Run("error - vendor name is empty", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		err := se.GenerateVendorCACSR(echo, GenerateVendorCACSRParams{Name: "  "})
		assert.EqualError(t, err, "code=400, message=name is invalid")
	})
	t.Run("error - vendor ID not set", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		err := se.GenerateVendorCACSR(echo, GenerateVendorCACSRParams{Name: "foo"})
		assert.EqualError(t, err, "code=500, message=invalid key identifier")
	})
}

func TestApiWrapper_SelfSignVendorCACertificate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		os.Setenv("NUTS_IDENTITY", "urn:oid:1.3.6.1.4.1.54851.4:4")
		defer os.Unsetenv("NUTS_IDENTITY")
		core.NutsConfig().Load(&cobra.Command{})

		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Blob(http.StatusOK, "application/x-pem-file", gomock.Any())

		se.SelfSignVendorCACertificate(echo, SelfSignVendorCACertificateParams{Name: "foo"})
	})
	t.Run("error - vendor name is empty", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		err := se.SelfSignVendorCACertificate(echo, SelfSignVendorCACertificateParams{Name: "  "})
		assert.EqualError(t, err, "code=400, message=name is invalid")
	})
	t.Run("error - vendor ID not set", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		err := se.SelfSignVendorCACertificate(echo, SelfSignVendorCACertificateParams{Name: "foo"})
		assert.EqualError(t, err, "code=500, message=invalid key identifier")
	})
}

func TestApiWrapper_GenerateKeyPair(t *testing.T) {
	legalEntity := Identifier("test")
	t.Run("GenerateKeyPairAPI call returns 200 with pub in PEM format", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{})
		echo.EXPECT().String(http.StatusOK, pubKeyMatcher{})

		se.GenerateKeyPair(echo, GenerateKeyPairParams{LegalEntity: legalEntity})
	})

	t.Run("GenerateKeyPairAPI call returns 409 with overwrite=false", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)
		se.C.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: string(legalEntity)}), false)
		echo.EXPECT().String(http.StatusConflict, gomock.Any())

		overwrite := false
		se.GenerateKeyPair(echo, GenerateKeyPairParams{LegalEntity: legalEntity, Overwrite: &overwrite})
	})

	t.Run("GenerateKeyPairAPI call returns 200 with overwrite=true", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{})
		echo.EXPECT().String(http.StatusOK, pubKeyMatcher{})

		overwrite := true
		se.GenerateKeyPair(echo, GenerateKeyPairParams{LegalEntity: legalEntity, Overwrite: &overwrite})
	})

	t.Run("GenerateKeyPairAPI call returns 200 with pub in JWK format", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{Header: http.Header{"Accept": []string{"application/json"}}})
		echo.EXPECT().JSON(http.StatusOK, jwkMatcher{})

		se.GenerateKeyPair(echo, GenerateKeyPairParams{LegalEntity: legalEntity})
	})

	t.Run("GenerateKeyPairAPI returns error if generating the key gives an error", func(t *testing.T) {
		se := apiWrapper(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		if err := se.GenerateKeyPair(echo, GenerateKeyPairParams{}); err != nil {
			if !errors.Is(err, pkg.ErrInvalidKeyIdentifier) {
				t.Errorf("Expected error [%s], got [%s]", pkg.ErrInvalidKeyIdentifier, err)
			}
		} else {
			t.Error("Expected error")
		}
	})

	t.Run("PublicKey returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cl := mock2.NewMockClient(ctrl)
		echo := mock.NewMockContext(ctrl)

		se := ApiWrapper{
			C: cl,
		}

		// empty mock
		echo.EXPECT().Request().Return(&http.Request{})

		// key generation is ok
		cl.EXPECT().GenerateKeyPair(key, false).Return(nil, nil).AnyTimes()

		// getting pub key goes boom!
		cl.EXPECT().GetPublicKeyAsPEM(key).Return("", errors.New("boom"))

		err := se.GenerateKeyPair(echo, GenerateKeyPairParams{LegalEntity: legalEntity})

		assert.NotNil(t, err)
	})
}

func TestApiWrapper_Encrypt(t *testing.T) {
	client := apiWrapper(t)
	crypto := client.C.(*pkg.Crypto)
	crypto.Config.Keysize = pkg.MinKeySize // required for RSA OAEP encryption
	plaintext := "for your eyes only"
	client.C.GenerateKeyPair(key, false)
	pemKey, _ := client.C.GetPublicKeyAsPEM(key)

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.Encrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=missing body in request"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Encrypt API call returns 200 with encrypted message", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		pk := PublicKey(pemKey)
		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier(key.Owner()),
					PublicKey:   &pk,
				},
			},
			PlainText: base64.StdEncoding.EncodeToString([]byte(plaintext)),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		_ = client.Encrypt(echo)
	})

	t.Run("Illegal json gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader([]byte("{"))),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Encrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=Error unmarshalling json: unexpected end of JSON input"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing subjects gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{},
			PlainText:              base64.StdEncoding.EncodeToString([]byte(plaintext)),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Encrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=missing encryptRequestSubjects in encryptRequest"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing plainText gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		pk := PublicKey(pemKey)
		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier(key.Owner()),
					PublicKey:   &pk,
				},
			},
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Encrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=missing plainText in encryptRequest"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Illegal BASE64 encoding gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		pk := PublicKey(pemKey)
		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier("UNKNOWN"),
					PublicKey:   &pk,
				},
			},
			PlainText: plaintext,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Encrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=Illegal base64 encoded string: illegal base64 data at input byte 3"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Broken public key gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		pk := PublicKey(pemKey[1:])
		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier("UNKNOWN"),
					PublicKey:   &pk,
				},
			},
			PlainText: base64.StdEncoding.EncodeToString([]byte(plaintext)),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Encrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "invalid key in encryptRequestSubjects")
		}
	})

	t.Run("Broken jwk gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier("UNKNOWN"),
					Jwk:         &JWK{},
				},
			},
			PlainText: base64.StdEncoding.EncodeToString([]byte(plaintext)),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Encrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "invalid key in encryptRequestSubjects")
		}
	})

	t.Run("Missing key gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier("UNKNOWN"),
				},
			},
			PlainText: base64.StdEncoding.EncodeToString([]byte(plaintext)),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Encrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "missing key in encryptRequestSubjects")
		}
	})
}

func TestApiWrapper_Decrypt(t *testing.T) {
	client := apiWrapper(t)
	crypto := client.C.(*pkg.Crypto)
	crypto.Config.Keysize = pkg.MinKeySize // required for RSA OAEP encryption

	plaintext := "for your eyes only"
	client.C.GenerateKeyPair(key, false)
	pubKey, _ := client.C.GetPublicKeyAsJWK(key)
	encRecord, _ := client.C.EncryptKeyAndPlainText([]byte(plaintext), []jwk.Key{pubKey})

	t.Run("Decrypt API call returns 200 with decrypted message", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity:   Identifier(key.Owner()),
			CipherText:    base64.StdEncoding.EncodeToString(encRecord.CipherText),
			CipherTextKey: base64.StdEncoding.EncodeToString(encRecord.CipherTextKeys[0]),
			Nonce:         base64.StdEncoding.EncodeToString(encRecord.Nonce),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		client.Decrypt(echo)
	})

	t.Run("Decrypt API call returns 400 for broken cipherText", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity:   Identifier(key.Owner()),
			CipherText:    base64.StdEncoding.EncodeToString(encRecord.CipherText[1:]),
			CipherTextKey: base64.StdEncoding.EncodeToString(encRecord.CipherTextKeys[0]),
			Nonce:         base64.StdEncoding.EncodeToString(encRecord.Nonce),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "error decrypting request")
		}
	})

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "missing body in request")
		}
	})

	t.Run("Illegal json gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader([]byte("{"))),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Error unmarshalling json: unexpected end of JSON input")
		}
	})

	t.Run("Reading error gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{
			Body: errorCloser{},
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "error reading request: error")
		}
	})

	t.Run("Missing legalEntity gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "missing legalEntityURI in request")
		}
	})

	t.Run("Missing nonce gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity:   Identifier(key.Owner()),
			CipherText:    base64.StdEncoding.EncodeToString(encRecord.CipherText),
			CipherTextKey: base64.StdEncoding.EncodeToString(encRecord.CipherTextKeys[0]),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "error decrypting request: illegal nonce given")
		}
	})

	t.Run("Missing CipherText gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity:   Identifier(key.Owner()),
			CipherTextKey: base64.StdEncoding.EncodeToString(encRecord.CipherTextKeys[0]),
			Nonce:         base64.StdEncoding.EncodeToString(encRecord.Nonce),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "error decrypting request: cipher: message authentication failed")
		}
	})

	t.Run("Missing CipherTextKey gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity: Identifier(key.Owner()),
			CipherText:  base64.StdEncoding.EncodeToString(encRecord.CipherText),
			Nonce:       base64.StdEncoding.EncodeToString(encRecord.Nonce),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "error decrypting request: crypto/rsa: decryption error")
		}
	})
}

func TestApiWrapper_ExternalIdFor(t *testing.T) {
	client := apiWrapper(t)

	subject := Identifier("test")
	actor := Identifier("test")
	client.C.GenerateKeyPair(key, false)

	t.Run("ExternalId API call returns 200 with new externalId", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := ExternalIdRequest{
			LegalEntity: Identifier(key.Owner()),
			Subject:     subject,
			Actor:       actor,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		client.ExternalId(echo)
	})

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.ExternalId(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=missing body in request"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Reading error gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{
			Body: errorCloser{},
		}

		echo.EXPECT().Request().Return(request)

		err := client.ExternalId(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=error reading request: error"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Illegal json gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader([]byte("{"))),
		}

		echo.EXPECT().Request().Return(request)

		err := client.ExternalId(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=Error unmarshalling json: unexpected end of JSON input"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("missing legalEntity gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := ExternalIdRequest{
			Subject: subject,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.ExternalId(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=missing legalEntityURI in request"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("missing subjects gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := ExternalIdRequest{
			LegalEntity: Identifier(key.Owner()),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.ExternalId(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=missing subjectURI in request"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("unknown legalEntity gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := ExternalIdRequest{
			LegalEntity: Identifier("UNKNOWN"),
			Subject:     subject,
			Actor:       actor,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.ExternalId(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), storage.ErrNotFound.Error())
		}
	})
}

func TestDefaultCryptoEngine_Sign(t *testing.T) {
	client := apiWrapper(t)

	client.C.GenerateKeyPair(key, false)

	t.Run("Missing plainText returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignRequest{
			LegalEntity: Identifier(key.Owner()),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Sign(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=missing plainText"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error %s, got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing legalEntity returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignRequest{
			PlainText: "text",
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Sign(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=missing legalEntityURI"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error %s, got: [%s]", expected, err.Error())
		}
	})

	t.Run("All OK returns 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignRequest{
			LegalEntity: Identifier(key.Owner()),
			PlainText:   "text",
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		err := client.Sign(echo)

		if err != nil {
			t.Errorf("Expected no error got [%s]", err.Error())
		}
	})

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.Sign(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=missing body in request"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})
}

func TestApiWrapper_SignJwt(t *testing.T) {
	client := apiWrapper(t)

	client.C.GenerateKeyPair(key, false)

	t.Run("Missing claims returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignJwtRequest{
			LegalEntity: Identifier(key.Owner()),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.SignJwt(echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing claims")
	})

	t.Run("Missing legalEntity returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignJwtRequest{
			Claims: map[string]interface{}{"iss": "nuts"},
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.SignJwt(echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing legalEntityURI")
	})

	t.Run("All OK returns 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignJwtRequest{
			LegalEntity: Identifier(key.Owner()),
			Claims:      map[string]interface{}{"iss": "nuts"},
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().String(http.StatusOK, gomock.Any())

		err := client.SignJwt(echo)

		assert.Nil(t, err)
	})

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.SignJwt(echo)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code=400, message=missing body in request")
	})
}

func TestDefaultCryptoEngine_Verify(t *testing.T) {
	client := apiWrapper(t)

	client.C.GenerateKeyPair(key, false)

	pemPubKey, _ := client.C.GetPublicKeyAsPEM(key)
	jwk, _ := client.C.GetPublicKeyAsJWK(key)
	plainText := "text"
	base64PlainText := base64.StdEncoding.EncodeToString([]byte(plainText))
	signature, _ := client.C.Sign([]byte(plainText), key)
	hexSignature := hex.EncodeToString(signature)

	t.Run("Missing publicKey/JWK returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := VerifyRequest{
			PlainText: plainText,
			Signature: hexSignature,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Verify(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "missing publicKey/JWK in verifyRequest")
		}
	})

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.Verify(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "missing body in request")
		}
	})

	t.Run("Missing plainText returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		pk := PublicKey(pemPubKey)
		jsonRequest := VerifyRequest{
			PublicKey: &pk,
			Signature: hexSignature,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Verify(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "missing plainText in verifyRequest")
		}
	})

	t.Run("Missing signature returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		pk := PublicKey(pemPubKey)
		jsonRequest := VerifyRequest{
			PlainText: plainText,
			PublicKey: &pk,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Verify(echo)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "missing signature in verifyRequest")
		}
	})

	t.Run("All OK returns 200", func(t *testing.T) {
		client := apiWrapper(t)

		client.C.GenerateKeyPair(key, false)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		t.Run("using public key", func(t *testing.T) {
			pk := PublicKey(pemPubKey)
			jsonRequest := VerifyRequest{
				Signature: hexSignature,
				PublicKey: &pk,
				PlainText: base64PlainText,
			}

			json, _ := json.Marshal(jsonRequest)
			request := &http.Request{
				Body: ioutil.NopCloser(bytes.NewReader(json)),
			}

			echo.EXPECT().Request().Return(request)
			echo.EXPECT().JSON(http.StatusOK, gomock.Any())

			err := client.Verify(echo)

			assert.NoError(t, err)
		})

		t.Run("using jwk", func(t *testing.T) {
			pk, _ := cert.JwkToMap(jwk)
			jwk := JWK(pk)
			jsonRequest := VerifyRequest{
				Signature: hexSignature,
				Jwk:       &jwk,
				PlainText: base64PlainText,
			}

			json, _ := json.Marshal(jsonRequest)
			request := &http.Request{
				Body: ioutil.NopCloser(bytes.NewReader(json)),
			}

			echo.EXPECT().Request().Return(request)
			echo.EXPECT().JSON(http.StatusOK, gomock.Any())

			err := client.Verify(echo)

			assert.NoError(t, err)
		})
	})

	t.Run("Broken key returns 400", func(t *testing.T) {
		client := apiWrapper(t)

		client.C.GenerateKeyPair(key, false)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		t.Run("using public key", func(t *testing.T) {
			pk := PublicKey(pemPubKey[1:])
			jsonRequest := VerifyRequest{
				Signature: hexSignature,
				PublicKey: &pk,
				PlainText: base64PlainText,
			}

			json, _ := json.Marshal(jsonRequest)
			request := &http.Request{
				Body: ioutil.NopCloser(bytes.NewReader(json)),
			}

			echo.EXPECT().Request().Return(request)

			err := client.Verify(echo)

			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "invalid publicKey in verifyRequest")
			}
		})

		t.Run("using jwk", func(t *testing.T) {
			pk, _ := cert.JwkToMap(jwk)
			pk["kty"] = "unknown"
			jwk := JWK(pk)
			jsonRequest := VerifyRequest{
				Signature: hexSignature,
				Jwk:       &jwk,
				PlainText: base64PlainText,
			}

			json, _ := json.Marshal(jsonRequest)
			request := &http.Request{
				Body: ioutil.NopCloser(bytes.NewReader(json)),
			}

			echo.EXPECT().Request().Return(request)

			err := client.Verify(echo)

			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "invalid JWK in verifyRequest")
			}
		})
	})
}

func TestApiWrapper_PublicKey(t *testing.T) {
	client := apiWrapper(t)

	client.C.GenerateKeyPair(key, false)

	t.Run("PublicKey API call returns 200", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{})
		echo.EXPECT().String(http.StatusOK, gomock.Any())

		_ = client.PublicKey(echo, "test")
	})

	t.Run("PublicKey API call returns JWK", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{Header: http.Header{"Accept": []string{"application/json"}}})
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		_ = client.PublicKey(echo, "test")
	})

	t.Run("PublicKey API call returns 404 for unknown", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{})
		echo.EXPECT().NoContent(http.StatusNotFound)

		_ = client.PublicKey(echo, "not")
	})

	t.Run("PublicKey API call returns 404 for unknown, JWK requested", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().Request().Return(&http.Request{Header: http.Header{"Accept": []string{"application/json"}}})
		echo.EXPECT().NoContent(http.StatusNotFound)

		_ = client.PublicKey(echo, "not")
	})

	t.Run("PublicKey API call returns 400 for empty urn", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		err := client.PublicKey(echo, "")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "incorrect organization urn in request")
		}
	})
}

func apiWrapper(t *testing.T) *ApiWrapper {
	backend, _ := storage.NewFileSystemBackend(io.TestDirectory(t))
	crypto := pkg.Crypto{
		Storage: backend,
		Config:  pkg.DefaultCryptoConfig(),
	}
	crypto.Config.Keysize = 1024

	return &ApiWrapper{C: &crypto}
}

type errorCloser struct{}

func (errorCloser) Read([]byte) (n int, err error) {
	return 0, errors.New("error")
}

func (errorCloser) Close() error {
	return errors.New("error")
}
