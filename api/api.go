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
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"regexp"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/sirupsen/logrus"
)

type ApiWrapper struct {
	C pkg.Client
}

// GenerateKeyPair is the implementation of the REST service call POST /crypto/generate
// It returns the public key for the given legal entity in either PEM or JWK format depending on the accept-header. Default is PEM (backwards compatibility)
func (w *ApiWrapper) GenerateKeyPair(ctx echo.Context, params GenerateKeyPairParams) error {
	le := types.LegalEntity{URI: string(params.LegalEntity)}
	if err := w.C.GenerateKeyPairFor(le); err != nil {
		return err
	}

	acceptHeader := ctx.Request().Header.Get("Accept")

	// starts with so we can ignore any +
	if ct, _, _ := mime.ParseMediaType(acceptHeader); ct == "application/json" {
		jwk, err := w.C.PublicKeyInJWK(le)
		if err != nil {
			return err
		}

		return ctx.JSON(http.StatusOK, jwk)
	}

	// backwards compatible PEM format is the default
	pub, err := w.C.PublicKeyInPEM(le)
	if err != nil {
		return err
	}

	return ctx.String(http.StatusOK, pub)
}

// Encrypt is the implementation of the REST service call POST /crypto/encrypt
func (w *ApiWrapper) Encrypt(ctx echo.Context) error {
	buf, err := readBody(ctx)
	if err != nil {
		return err
	}

	var encryptRequest = &EncryptRequest{}
	err = json.Unmarshal(buf, encryptRequest)

	if err != nil {
		msg := fmt.Sprintf("Error unmarshalling json: %v", err.Error())
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	if len(encryptRequest.EncryptRequestSubjects) == 0 {
		msg := "missing encryptRequestSubjects in encryptRequest"
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	if len(encryptRequest.PlainText) == 0 {
		msg := "missing plainText in encryptRequest"
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	var pubKeys []jwk.Key
	var legalEntities []Identifier
	for _, e := range encryptRequest.EncryptRequestSubjects {
		if e.PublicKey == nil && e.Jwk == nil {
			msg := "missing key in encryptRequestSubjects"
			logrus.Error(msg)
			return echo.NewHTTPError(http.StatusBadRequest, msg)
		}

		var (
			j   jwk.Key
			err error
		)
		if e.Jwk != nil {
			j, err = pkg.MapToJwk(e.Jwk.AdditionalProperties)
			if err != nil {
				msg := "invalid key in encryptRequestSubjects"
				logrus.Error(msg)
				return echo.NewHTTPError(http.StatusBadRequest, msg)
			}
		} else {
			if e.PublicKey != nil {
				j, err = pkg.PemToJwk([]byte(*e.PublicKey))
				if err != nil {
					msg := "invalid key in encryptRequestSubjects"
					logrus.Error(msg)
					return echo.NewHTTPError(http.StatusBadRequest, msg)
				}
			}
		}

		pubKeys = append(pubKeys, j)
		legalEntities = append(legalEntities, e.LegalEntity)
	}

	// encrypt with symmetric key and encrypt keys with asymmetric keys
	plainTextBytes, err := base64.StdEncoding.DecodeString(encryptRequest.PlainText)

	if err != nil {
		msg := fmt.Sprintf("Illegal base64 encoded string: %s", err.Error())
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	dect, err := w.C.EncryptKeyAndPlainTextWith(plainTextBytes, pubKeys)

	if err != nil {
		msg := fmt.Sprintf("Failed to encrypt plainText: %s", err.Error())
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	return ctx.JSON(http.StatusOK, dectToEncryptResponse(dect, legalEntities))
}

// Decrypt is the API handler function for decrypting a piece of data.
func (w *ApiWrapper) Decrypt(ctx echo.Context) error {
	buf, err := readBody(ctx)
	if err != nil {
		return err
	}

	var decryptRequest = &DecryptRequest{}
	err = json.Unmarshal(buf, decryptRequest)

	if err != nil {
		msg := fmt.Sprintf("Error unmarshalling json: %v", err.Error())
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	if len(decryptRequest.LegalEntity) == 0 {
		msg := "missing legalEntityURI in request"
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	dect, err := decryptRequestToDect(*decryptRequest)
	if err != nil {
		msg := fmt.Sprintf("error decrypting request: %v", err)
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	plainTextBytes, err := w.C.DecryptKeyAndCipherTextFor(dect, types.LegalEntity{URI: string(decryptRequest.LegalEntity)})

	if err != nil {
		msg := fmt.Sprintf("error decrypting request: %v", err)
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	decryptResponse := DecryptResponse{
		PlainText: base64.StdEncoding.EncodeToString(plainTextBytes),
	}

	return ctx.JSON(http.StatusOK, decryptResponse)
}

// ExternalId is the API handler function for generating a unique external identifier for a given identifier and legalEntity.
func (w *ApiWrapper) ExternalId(ctx echo.Context) error {
	buf, err := readBody(ctx)
	if err != nil {
		return err
	}

	var request = &ExternalIdRequest{}
	err = json.Unmarshal(buf, request)

	if err != nil {
		msg := fmt.Sprintf("Error unmarshalling json: %v", err.Error())
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	if len(request.LegalEntity) == 0 {
		msg := "missing legalEntityURI in request"
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}
	if len(request.Subject) == 0 {
		msg := "missing subjectURI in request"
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	shaBytes, err := w.C.ExternalIdFor(string(request.Subject), string(request.Actor), types.LegalEntity{URI: string(request.LegalEntity)})
	if err != nil {
		msg := fmt.Sprintf("error getting externalId: %v", err)
		logrus.Error(msg)
		return echo.NewHTTPError(http.StatusInternalServerError, msg)
	}

	sha := hex.EncodeToString(shaBytes)

	externalIdResponse := ExternalIdResponse{
		ExternalId: sha,
	}

	return ctx.JSON(http.StatusOK, externalIdResponse)
}

func (w *ApiWrapper) Sign(ctx echo.Context) error {
	buf, err := readBody(ctx)
	if err != nil {
		return err
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

func (w *ApiWrapper) SignJwt(ctx echo.Context) error {
	buf, err := readBody(ctx)
	if err != nil {
		return err
	}

	var signRequest = &SignJwtRequest{}
	err = json.Unmarshal(buf, signRequest)

	if err != nil {
		logrus.Error(err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if len(signRequest.LegalEntity) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing legalEntityURI")
	}

	if len(signRequest.Claims) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "missing claims")
	}

	le := types.LegalEntity{URI: string(signRequest.LegalEntity)}
	sig, err := w.C.SignJwtFor(signRequest.Claims, le)

	if err != nil {
		logrus.Error(err.Error())
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return ctx.String(http.StatusOK, sig)
}

func (w *ApiWrapper) Verify(ctx echo.Context) error {
	buf, err := readBody(ctx)
	if err != nil {
		return err
	}

	var verifyRequest = &VerifyRequest{}
	err = json.Unmarshal(buf, verifyRequest)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	if verifyRequest.PublicKey == nil && verifyRequest.Jwk == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "missing publicKey/JWK in verifyRequest")
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

	var j jwk.Key
	if verifyRequest.Jwk != nil {
		j, err = pkg.MapToJwk(verifyRequest.Jwk.AdditionalProperties)
	} else {
		if verifyRequest.PublicKey != nil {
			j, err = pkg.PemToJwk([]byte(*verifyRequest.PublicKey))
		}
	}

	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid publicKey/JWK in verifyRequest")
	}

	valid, err := w.C.VerifyWith(plainTextBytes, sigBytes, j)

	if err != nil {
		logrus.Error(err.Error())
		return err
	}

	verifyResponse := VerifyResponse{
		Outcome: valid,
	}

	return ctx.JSON(http.StatusOK, verifyResponse)
}

// PublicKey returns a public key for the given urn. The urn represents a legal entity. The api returns the public key either in PEM or JWK format.
// It uses the accept header to determine this. Default is PEM (text/plain), only when application/json is requested will it return JWK.
func (w *ApiWrapper) PublicKey(ctx echo.Context, urn string) error {
	if match, err := regexp.MatchString(`^\S+$`, urn); !match || err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "incorrect organization urn in request")
	}

	le := types.LegalEntity{URI: urn}
	acceptHeader := ctx.Request().Header.Get("Accept")

	// starts with so we can ignore any +
	if ct, _, _ := mime.ParseMediaType(acceptHeader); ct == "application/json" {
		jwk, err := w.C.PublicKeyInJWK(le)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return ctx.NoContent(404)
			}
			logrus.Error(err.Error())
			return err
		}

		return ctx.JSON(http.StatusOK, jwk)
	}

	// backwards compatible PEM format is the default
	pub, err := w.C.PublicKeyInPEM(le)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ctx.NoContent(404)
		}
		logrus.Error(err.Error())
		return err
	}

	return ctx.String(http.StatusOK, pub)
}

func readBody(ctx echo.Context) ([]byte, error) {
	req := ctx.Request()
	if req.Body == nil {
		msg := "missing body in request"
		logrus.Error(msg)
		return nil, echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	buf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		msg := fmt.Sprintf("error reading request: %v", err)
		logrus.Error(msg)
		return nil, echo.NewHTTPError(http.StatusBadRequest, msg)
	}

	return buf, nil
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
