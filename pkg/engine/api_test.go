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

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/generated"
	"github.com/nuts-foundation/nuts-go/mock"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestServiceWrapper_GenerateKeyPair(t *testing.T) {
	t.Run("GenerateKeyPairAPI call returns 201 CREATED", func(t *testing.T) {
		se := createTempEngine()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().NoContent(http.StatusCreated)

		se.GenerateKeyPair(echo, generated.GenerateKeyPairParams{LegalEntityURI: "test"})
	})
}

func TestServiceWrapper_Encrypt(t *testing.T) {
	t.Run("Encrypt API call returns 200 with encrypted message", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"
		client.GenerateKeyPairFor(legalEntity)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := generated.EncryptRequest{
			LegalEntityURI: generated.LegalEntityURI(legalEntity.URI),
			PlainText:      base64.StdEncoding.EncodeToString([]byte(plaintext)),
		}

		json, _ := json.Marshal(jsonRequest)
		request := &http.Request{
			Body: ioutil.NopCloser(bytes.NewReader(json)),
		}

		echo.EXPECT().Request().Return(request)
		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		client.Encrypt(echo)
	})
}

func TestServiceWrapper_DecryptKeyAndCipherTextFor(t *testing.T) {
	t.Run("Decrypt API call returns 200 with decrypted message", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"
		client.GenerateKeyPairFor(legalEntity)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		encRecord, _ := client.EncryptKeyAndPlainTextFor([]byte(plaintext), legalEntity)
		jsonRequest := generated.DecryptRequest{
			LegalEntityURI: generated.LegalEntityURI(legalEntity.URI),
			CipherText:     base64.StdEncoding.EncodeToString(encRecord.CipherText),
			CipherTextKey:  base64.StdEncoding.EncodeToString(encRecord.CipherTextKey),
			Nonce:          base64.StdEncoding.EncodeToString(encRecord.Nonce),
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

func TestServiceWrapper_ExternalIdFor(t *testing.T) {
	t.Run("ExternalId API call returns 200 with new externalId", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		subject := generated.SubjectURI("test")
		client.GenerateKeyPairFor(legalEntity)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		jsonRequest := generated.ExternalIdRequest{
			LegalEntityURI: generated.LegalEntityURI(legalEntity.URI),
			SubjectURI:     subject,
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
