// Package api provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package api

import (
	"fmt"
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
	"net/http"
)

// DecryptRequest defines model for DecryptRequest.
type DecryptRequest struct {
	CipherText    string     `json:"cipherText"`
	CipherTextKey string     `json:"cipherTextKey"`
	LegalEntity   Identifier `json:"legalEntity"`
	Nonce         string     `json:"nonce"`
}

// DecryptResponse defines model for DecryptResponse.
type DecryptResponse struct {
	PlainText string `json:"plainText"`
}

// EncryptRequest defines model for EncryptRequest.
type EncryptRequest struct {
	EncryptRequestSubjects []EncryptRequestSubject `json:"encryptRequestSubjects"`
	PlainText              string                  `json:"plainText"`
}

// EncryptRequestSubject defines model for EncryptRequestSubject.
type EncryptRequestSubject struct {
	LegalEntity Identifier `json:"legalEntity"`
	PublicKey   PublicKey  `json:"publicKey"`
}

// EncryptResponse defines model for EncryptResponse.
type EncryptResponse struct {
	CipherText             string                 `json:"cipherText"`
	EncryptResponseEntries []EncryptResponseEntry `json:"encryptResponseEntries"`
	Nonce                  string                 `json:"nonce"`
}

// EncryptResponseEntry defines model for EncryptResponseEntry.
type EncryptResponseEntry struct {
	CipherTextKey string     `json:"cipherTextKey"`
	LegalEntity   Identifier `json:"legalEntity"`
}

// ExternalIdRequest defines model for ExternalIdRequest.
type ExternalIdRequest struct {
	Actor       Identifier `json:"actor"`
	LegalEntity Identifier `json:"legalEntity"`
	Subject     Identifier `json:"subject"`
}

// ExternalIdResponse defines model for ExternalIdResponse.
type ExternalIdResponse struct {
	ExternalId string `json:"externalId"`
}

// Identifier defines model for Identifier.
type Identifier string

// PublicKey defines model for PublicKey.
type PublicKey string

// SignRequest defines model for SignRequest.
type SignRequest struct {
	LegalEntity Identifier `json:"legalEntity"`
	PlainText   string     `json:"plainText"`
}

// SignResponse defines model for SignResponse.
type SignResponse struct {
	Signature string `json:"signature"`
}

// VerifyRequest defines model for VerifyRequest.
type VerifyRequest struct {
	PlainText string    `json:"plainText"`
	PublicKey PublicKey `json:"publicKey"`
	Signature string    `json:"signature"`
}

// VerifyResponse defines model for VerifyResponse.
type VerifyResponse struct {
	Outcome bool `json:"outcome"`
}

// decryptJSONBody defines parameters for Decrypt.
type decryptJSONBody DecryptRequest

// encryptJSONBody defines parameters for Encrypt.
type encryptJSONBody EncryptRequest

// externalIdJSONBody defines parameters for ExternalId.
type externalIdJSONBody ExternalIdRequest

// GenerateKeyPairParams defines parameters for GenerateKeyPair.
type GenerateKeyPairParams struct {
	LegalEntity Identifier `json:"legalEntity"`
}

// signJSONBody defines parameters for Sign.
type signJSONBody SignRequest

// verifyJSONBody defines parameters for Verify.
type verifyJSONBody VerifyRequest

// DecryptRequestBody defines body for Decrypt for application/json ContentType.
type DecryptJSONRequestBody decryptJSONBody

// EncryptRequestBody defines body for Encrypt for application/json ContentType.
type EncryptJSONRequestBody encryptJSONBody

// ExternalIdRequestBody defines body for ExternalId for application/json ContentType.
type ExternalIdJSONRequestBody externalIdJSONBody

// SignRequestBody defines body for Sign for application/json ContentType.
type SignJSONRequestBody signJSONBody

// VerifyRequestBody defines body for Verify for application/json ContentType.
type VerifyJSONRequestBody verifyJSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// decrypt a cipherText for the given legalEntity// (POST /crypto/decrypt)
	Decrypt(ctx echo.Context) error
	// encrypt a piece of data for a list of public keys/legalEntity's. A single symmetric keys will be used for all entries// (POST /crypto/encrypt)
	Encrypt(ctx echo.Context) error
	// calculate an externalId for a (custodian, subject, actor) triple// (POST /crypto/external_id)
	ExternalId(ctx echo.Context) error
	// Send a request for checking if the given combination has valid consent// (POST /crypto/generate)
	GenerateKeyPair(ctx echo.Context, params GenerateKeyPairParams) error
	// sign a piece of data with the private key of the given legalEntity// (POST /crypto/sign)
	Sign(ctx echo.Context) error
	// verify a signature given a public key, signature and the data// (POST /crypto/verify)
	Verify(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// Decrypt converts echo context to params.
func (w *ServerInterfaceWrapper) Decrypt(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Decrypt(ctx)
	return err
}

// Encrypt converts echo context to params.
func (w *ServerInterfaceWrapper) Encrypt(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Encrypt(ctx)
	return err
}

// ExternalId converts echo context to params.
func (w *ServerInterfaceWrapper) ExternalId(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.ExternalId(ctx)
	return err
}

// GenerateKeyPair converts echo context to params.
func (w *ServerInterfaceWrapper) GenerateKeyPair(ctx echo.Context) error {
	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params GenerateKeyPairParams
	// ------------- Required query parameter "legalEntity" -------------
	if paramValue := ctx.QueryParam("legalEntity"); paramValue != "" {

	} else {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Query argument legalEntity is required, but not found"))
	}

	err = runtime.BindQueryParameter("form", true, true, "legalEntity", ctx.QueryParams(), &params.LegalEntity)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter legalEntity: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GenerateKeyPair(ctx, params)
	return err
}

// Sign converts echo context to params.
func (w *ServerInterfaceWrapper) Sign(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Sign(ctx)
	return err
}

// Verify converts echo context to params.
func (w *ServerInterfaceWrapper) Verify(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Verify(ctx)
	return err
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router runtime.EchoRouter, si ServerInterface) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.POST("/crypto/decrypt", wrapper.Decrypt)
	router.POST("/crypto/encrypt", wrapper.Encrypt)
	router.POST("/crypto/external_id", wrapper.ExternalId)
	router.POST("/crypto/generate", wrapper.GenerateKeyPair)
	router.POST("/crypto/sign", wrapper.Sign)
	router.POST("/crypto/verify", wrapper.Verify)

}

