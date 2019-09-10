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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-go-core/mock"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestApiWrapper_GenerateKeyPair(t *testing.T) {
	t.Run("GenerateKeyPairAPI call returns 201 CREATED", func(t *testing.T) {
		se := apiWrapper()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().NoContent(http.StatusCreated)

		se.GenerateKeyPair(echo, GenerateKeyPairParams{LegalEntity: "test"})
	})

	t.Run("GenerateKeyPairAPI returns error if generating the key gives an error", func(t *testing.T) {
		se := apiWrapper()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		if err := se.GenerateKeyPair(echo, GenerateKeyPairParams{}); err != nil {
			expected := "Missing legalEntity URI"
			if !strings.Contains(err.Error(), expected) {
				t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
			}
		} else {
			t.Error("Expected error")
		}
	})
}

func TestApiWrapper_Encrypt(t *testing.T) {
	client := apiWrapper()
	defer emptyTemp()
	legalEntity := types.LegalEntity{URI: "test"}
	plaintext := "for your eyes only"
	client.C.GenerateKeyPairFor(legalEntity)
	pubKey, _ := client.C.Storage.GetPublicKey(legalEntity)
	pemKey, _ := pkg.PublicKeyToPem(pubKey)

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

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier(legalEntity.URI),
					PublicKey:   PublicKey(pemKey),
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

		client.Encrypt(echo)
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

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier(legalEntity.URI),
					PublicKey:   PublicKey(pemKey),
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

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier("UNKNOWN"),
					PublicKey:   PublicKey(pemKey),
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

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier("UNKNOWN"),
					PublicKey:   PublicKey(pemKey[1:]),
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

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=Failed to encrypt plainText: failed to decode PEM block containing public key, key is of the wrong type"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})
}

func TestApiWrapper_Decrypt(t *testing.T) {
	client := apiWrapper()
	defer emptyTemp()

	legalEntity := types.LegalEntity{URI: "test"}
	plaintext := "for your eyes only"
	client.C.GenerateKeyPairFor(legalEntity)
	pubKey, _ := client.C.PublicKey(legalEntity)
	encRecord, _ := client.C.EncryptKeyAndPlainTextWith([]byte(plaintext), []string{pubKey})

	t.Run("Decrypt API call returns 200 with decrypted message", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity:   Identifier(legalEntity.URI),
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

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=missing body in request"
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

		err := client.Decrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=Error unmarshalling json: unexpected end of JSON input"
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

		err := client.Decrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=error reading request: error"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
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

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=missing legalEntityURI in request"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing nonce gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity:   Identifier(legalEntity.URI),
			CipherText:    base64.StdEncoding.EncodeToString(encRecord.CipherText),
			CipherTextKey: base64.StdEncoding.EncodeToString(encRecord.CipherTextKeys[0]),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=error decrypting request: illegal nonce given"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing CipherText gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity:   Identifier(legalEntity.URI),
			CipherTextKey: base64.StdEncoding.EncodeToString(encRecord.CipherTextKeys[0]),
			Nonce:         base64.StdEncoding.EncodeToString(encRecord.Nonce),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=error decrypting request: cipher: message authentication failed"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing CipherTextKey gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := DecryptRequest{
			LegalEntity: Identifier(legalEntity.URI),
			CipherText:  base64.StdEncoding.EncodeToString(encRecord.CipherText),
			Nonce:       base64.StdEncoding.EncodeToString(encRecord.Nonce),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Decrypt(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=error decrypting request: crypto/rsa: decryption error"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})
}

func TestApiWrapper_ExternalIdFor(t *testing.T) {
	client := apiWrapper()
	defer emptyTemp()

	legalEntity := types.LegalEntity{URI: "test"}
	subject := Identifier("test")
	actor := Identifier("test")
	client.C.GenerateKeyPairFor(legalEntity)

	t.Run("ExternalId API call returns 200 with new externalId", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := ExternalIdRequest{
			LegalEntity: Identifier(legalEntity.URI),
			Subject:     subject,
			Actor:		 actor,
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
			LegalEntity: Identifier(legalEntity.URI),
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
			Actor:		 actor,
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

		expected := "code=500, message=error getting externalId: could not open private key for legalEntity: {UNKNOWN} with filename ../../temp/VU5LTk9XTg==_private.pem"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})
}

func TestDefaultCryptoEngine_Sign(t *testing.T) {
	client := apiWrapper()
	defer emptyTemp()

	legalEntity := types.LegalEntity{URI: "test"}
	client.C.GenerateKeyPairFor(legalEntity)

	t.Run("Missing plainText returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := SignRequest{
			LegalEntity: Identifier(legalEntity.URI),
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
			LegalEntity: Identifier(legalEntity.URI),
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

func TestDefaultCryptoEngine_Verify(t *testing.T) {
	client := apiWrapper()
	defer emptyTemp()

	legalEntity := types.LegalEntity{URI: "test"}
	client.C.GenerateKeyPairFor(legalEntity)

	pubKey, _ := client.C.Storage.GetPublicKey(legalEntity)
	pemPubKey, _ := pkg.PublicKeyToPem(pubKey)
	plainText := "text"
	base64PlainText := base64.StdEncoding.EncodeToString([]byte(plainText))
	signature, _ := client.C.SignFor([]byte(plainText), legalEntity)
	hexSignature := hex.EncodeToString(signature)

	t.Run("Missing publicKey returns 400", func(t *testing.T) {
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

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=missing publicKey in verifyRequest"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error %s, got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing body gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		request := &http.Request{}

		echo.EXPECT().Request().Return(request)

		err := client.Verify(echo)

		if err == nil {
			t.Error("Expected error got nothing")
			return
		}

		expected := "code=400, message=missing body in request"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing plainText returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := VerifyRequest{
			PublicKey: PublicKey(pemPubKey),
			Signature: hexSignature,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Verify(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=missing plainText in verifyRequest"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error %s, got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing signature returns 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := VerifyRequest{
			PlainText: plainText,
			PublicKey: PublicKey(pemPubKey),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)

		err := client.Verify(echo)

		if err == nil {
			t.Error("Expected error got nothing")
		}

		expected := "code=400, message=missing signature in verifyRequest"
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error %s, got: [%s]", expected, err.Error())
		}
	})

	t.Run("All OK returns 200", func(t *testing.T) {
		client := apiWrapper()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		client.C.GenerateKeyPairFor(legalEntity)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := VerifyRequest{
			Signature: hexSignature,
			PublicKey: PublicKey(pemPubKey),
			PlainText: base64PlainText,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		err := client.Verify(echo)

		if err != nil {
			t.Errorf("Expected no error got [%s]", err.Error())
		}
	})
}

func apiWrapper() *ApiWrapper {
	backend := pkg.Crypto{
		Storage: createTempStorage(),
		Config:  pkg.CryptoConfig{Keysize: types.ConfigKeySizeDefault},
	}

	return &ApiWrapper{C: &backend}
}


func createTempStorage() storage.Storage {
	b, _ := storage.NewFileSystemBackend("../../temp")
	return b
}

func emptyTemp() {
	err := os.RemoveAll("../../temp/")

	if err != nil {
		println(err.Error())
	}
}

type errorCloser struct{}

func (errorCloser) Read(p []byte) (n int, err error) {
	return 0, errors.New("error")
}

func (errorCloser) Close() error {
	return errors.New("error")
}
