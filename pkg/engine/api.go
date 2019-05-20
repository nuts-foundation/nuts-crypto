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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/golang/glog"
	"github.com/labstack/echo/v4"
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/generated"
	"io/ioutil"
	"net/http"
)

// implementation of pkg/generated/api_gen.go#ServerInterface

// GenerateKeyPair is the implementation of the REST service call POST /crypto/generate
func (ce *DefaultCryptoEngine) GenerateKeyPair(ctx echo.Context, params generated.GenerateKeyPairParams) error {
	if err := ce.GenerateKeyPairFor(types.LegalEntity{URI: string(params.LegalEntityURI)}); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusCreated)
}

// Encrypt is the implementation of the REST service call POST /crypto/encrypt
func (ce *DefaultCryptoEngine) Encrypt(ctx echo.Context) error {
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

// Decrypt is the API handler function for decrypting a piece of data.
func (ce *DefaultCryptoEngine) Decrypt(ctx echo.Context) error {
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

// ExternalId is the API handler function for generating a unique external identifier for a given identifier and legalEntity.
func (ce *DefaultCryptoEngine) ExternalId(ctx echo.Context) error {
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

func dectToEncryptResponse(dect types.DoubleEncryptedCipherText) generated.EncryptResponse {
	return generated.EncryptResponse{
		CipherText: base64.StdEncoding.EncodeToString(dect.CipherText),
		CipherTextKey: base64.StdEncoding.EncodeToString(dect.CipherTextKey),
		Nonce: base64.StdEncoding.EncodeToString(dect.Nonce),
	}
}
