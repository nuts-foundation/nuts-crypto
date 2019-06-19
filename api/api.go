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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

type ApiWrapper struct {
	C *pkg.Crypto
}

// GenerateKeyPair is the implementation of the REST service call POST /crypto/generate
func (w *ApiWrapper) GenerateKeyPair(ctx echo.Context, params GenerateKeyPairParams) error {
	if err := w.C.GenerateKeyPairFor(types.LegalEntity{URI: string(params.LegalEntity)}); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusCreated)
}

// Encrypt is the implementation of the REST service call POST /crypto/encrypt
func (w *ApiWrapper) Encrypt(ctx echo.Context) error {
	buf, err := ioutil.ReadAll(ctx.Request().Body)
	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	var encryptRequest = &EncryptRequest{}
	err = json.Unmarshal(buf, encryptRequest)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	if len(encryptRequest.EncryptRequestSubjects) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing encryptRequestSubjects in encryptRequest")
	}

	var pubKeys []string
	var legalEntities []Identifier
	for _, e := range encryptRequest.EncryptRequestSubjects {
		pubKeys = append(pubKeys, string(e.PublicKey))
		legalEntities = append(legalEntities, e.LegalEntity)
	}

	// encrypt with symmetric key and encrypt keys with asymmetric keys
	plainTextBytes, err := base64.StdEncoding.DecodeString(encryptRequest.PlainText)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	dect, err := w.C.EncryptKeyAndPlainTextWith(plainTextBytes, pubKeys)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	return ctx.JSON(http.StatusOK, dectToEncryptResponse(dect, legalEntities))
}

// Decrypt is the API handler function for decrypting a piece of data.
func (w *ApiWrapper) Decrypt(ctx echo.Context) error {
	buf, err := ioutil.ReadAll(ctx.Request().Body)
	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	var decryptRequest = &DecryptRequest{}
	err = json.Unmarshal(buf, decryptRequest)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	if len(decryptRequest.LegalEntity) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing legalEntityURI in decryptRequest")
	}

	dect, err := decryptRequestToDect(*decryptRequest)
	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	plainTextBytes, err := w.C.DecryptKeyAndCipherTextFor(dect, types.LegalEntity{URI: string(decryptRequest.LegalEntity)})

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	decryptResponse := DecryptResponse{
		PlainText: base64.StdEncoding.EncodeToString(plainTextBytes),
	}

	return ctx.JSON(http.StatusOK, decryptResponse)
}

// ExternalId is the API handler function for generating a unique external identifier for a given identifier and legalEntity.
func (w *ApiWrapper) ExternalId(ctx echo.Context) error {
	buf, err := ioutil.ReadAll(ctx.Request().Body)
	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	var request = &ExternalIdRequest{}
	err = json.Unmarshal(buf, request)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	if len(request.LegalEntity) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing legalEntityURI in request")
	}
	if len(request.Subject) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing subjectURI in request")
	}

	shaBytes, err := w.C.ExternalIdFor([]byte(request.Subject), types.LegalEntity{URI: string(request.LegalEntity)})
	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	sha := hex.EncodeToString(shaBytes)

	externalIdResponse := ExternalIdResponse{
		ExternalId: sha,
	}

	return ctx.JSON(http.StatusOK, externalIdResponse)
}

func (w *ApiWrapper) Sign(ctx echo.Context) error {
	buf, err := ioutil.ReadAll(ctx.Request().Body)
	if err != nil {
		logrus.Error(err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	var signRequest = &SignRequest{}
	err = json.Unmarshal(buf, signRequest)

	if err != nil {
		logrus.Error(err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if len(signRequest.LegalEntity) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing legalEntityURI")
	}

	if len(signRequest.PlainText) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing plainText")
	}

	plainTextBytes, err := base64.StdEncoding.DecodeString(signRequest.PlainText)

	if err != nil {
		logrus.Error(err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	le := types.LegalEntity{URI: string(signRequest.LegalEntity)}
	sig, err := w.C.SignFor(plainTextBytes, le)

	if err != nil {
		logrus.Error(err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	signResponse := SignResponse{
		Signature: hex.EncodeToString(sig),
	}

	return ctx.JSON(http.StatusOK, signResponse)
}

func (w *ApiWrapper) Verify(ctx echo.Context) error {
	buf, err := ioutil.ReadAll(ctx.Request().Body)
	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	var verifyRequest = &VerifyRequest{}
	err = json.Unmarshal(buf, verifyRequest)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	if len(verifyRequest.PublicKey) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing publicKey in verifyRequest")
	}

	if len(verifyRequest.Signature) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing signature in verifyRequest")
	}

	if len(verifyRequest.PlainText) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing plainText in verifyRequest")
	}

	plainTextBytes, err := base64.StdEncoding.DecodeString(verifyRequest.PlainText)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	sigBytes, err := hex.DecodeString(verifyRequest.Signature)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	valid, err := w.C.VerifyWith(plainTextBytes, sigBytes, string(verifyRequest.PublicKey))

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	verifyResponse := VerifyResponse{
		Outcome: valid,
	}

	return ctx.JSON(http.StatusOK, verifyResponse)
}

func decryptRequestToDect(gen DecryptRequest) (types.DoubleEncryptedCipherText, error) {
	dect := types.DoubleEncryptedCipherText{}
	var err error

	dect.CipherText, err = base64.StdEncoding.DecodeString(gen.CipherText)
	if err != nil {
		return dect, err
	}
	cipherTextKey, err := base64.StdEncoding.DecodeString(gen.CipherTextKey)
	if err != nil {
		return dect, err
	}
	dect.CipherTextKeys = append(dect.CipherTextKeys, cipherTextKey)
	dect.Nonce, err = base64.StdEncoding.DecodeString(gen.Nonce)
	if err != nil {
		return dect, err
	}

	return dect, nil
}

func dectToEncryptResponse(dect types.DoubleEncryptedCipherText, legalIdentities []Identifier) EncryptResponse {

	var encryptResponseEntries []EncryptResponseEntry

	for i := range dect.CipherTextKeys {
		encryptResponseEntries = append(encryptResponseEntries, EncryptResponseEntry{
			CipherTextKey: base64.StdEncoding.EncodeToString(dect.CipherTextKeys[i]),
			LegalEntity:   legalIdentities[i],
		})
	}

	return EncryptResponse{
		CipherText:             base64.StdEncoding.EncodeToString(dect.CipherText),
		EncryptResponseEntries: encryptResponseEntries,
		Nonce:                  base64.StdEncoding.EncodeToString(dect.Nonce),
	}
}
