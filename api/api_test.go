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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-go/mock"
	"io/ioutil"
	"net/http"
	"os"
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
			if err.Error() != expected {
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

	t.Run("Encrypt API call returns 200 with encrypted message", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{
				{
					LegalEntity: Identifier(legalEntity.URI),
					PublicKey:   PublicKey(string(publicKeyToBytes(pubKey))),
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

		expected := "code=400, message=unexpected end of JSON input"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})

	t.Run("Missing subjects gives 400", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := EncryptRequest{
			EncryptRequestSubjects: []EncryptRequestSubject{},
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

		expected := "code=400, message=missing encryptRequestSubjects in encryptRequest"
		if err.Error() != expected {
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
					PublicKey:   PublicKey(string(publicKeyToBytes(pubKey))),
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
		if err.Error() != expected {
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
					PublicKey:   PublicKey(string(publicKeyToBytes(pubKey))),
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
		if err.Error() != expected {
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
					PublicKey:   PublicKey(string(publicKeyToBytes(pubKey)[1:])),
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

		expected := "code=400, message=Failed to encrypt plainText: failed to decode PEM block containing public key"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got: [%s]", expected, err.Error())
		}
	})
}

func TestApiWrapper_DecryptKeyAndCipherTextFor(t *testing.T) {
	t.Run("Decrypt API call returns 200 with decrypted message", func(t *testing.T) {
		client := apiWrapper()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"
		client.C.GenerateKeyPairFor(legalEntity)
		pubKey, _ := client.C.PublicKey(legalEntity)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		encRecord, _ := client.C.EncryptKeyAndPlainTextWith([]byte(plaintext), []string{pubKey})
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
}

func TestApiWrapper_ExternalIdFor(t *testing.T) {
	t.Run("ExternalId API call returns 200 with new externalId", func(t *testing.T) {
		client := apiWrapper()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		subject := Identifier("test")
		client.C.GenerateKeyPairFor(legalEntity)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := ExternalIdRequest{
			LegalEntity: Identifier(legalEntity.URI),
			Subject:     subject,
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		client.ExternalId(echo)
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

		if err.Error() != "code=400, message=missing plainText" {
			t.Errorf("Expected error code=400, message=missing plainText, got: [%s]", err.Error())
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

		if err.Error() != "code=400, message=missing legalEntityURI" {
			t.Errorf("Expected error code=400, message=missing legalEntityURI, got: [%s]", err.Error())
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
}

func TestDefaultCryptoEngine_Verify(t *testing.T) {
	client := apiWrapper()
	defer emptyTemp()

	legalEntity := types.LegalEntity{URI: "test"}
	client.C.GenerateKeyPairFor(legalEntity)

	pubKey, _ := client.C.Storage.GetPublicKey(legalEntity)
	pemPubKey := string(publicKeyToBytes(pubKey))
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

		if err.Error() != "code=400, message=missing publicKey in verifyRequest" {
			t.Errorf("Expected error code=400, message=missing publicKey in verifyRequest, got: [%s]", err.Error())
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

		if err.Error() != "code=400, message=missing plainText in verifyRequest" {
			t.Errorf("Expected error code=400, message=missing plainText in verifyRequest, got: [%s]", err.Error())
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

		if err.Error() != "code=400, message=missing signature in verifyRequest" {
			t.Errorf("Expected error code=400, message=missing signature in verifyRequest, got: [%s]", err.Error())
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

func publicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1 := x509.MarshalPKCS1PublicKey(pub)

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

func apiWrapper() *ApiWrapper {
	backend := pkg.Crypto{
		Storage: createTempStorage(),
		Config:  pkg.CryptoConfig{Keysize: types.ConfigKeySizeDefault},
	}

	return &ApiWrapper{C: &backend}
}

func serviceInterfaceWrapper() *ServerInterfaceWrapper {
	return &ServerInterfaceWrapper{
		Handler: apiWrapper(),
	}
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
