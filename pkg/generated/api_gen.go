// Package generated provides primitives to interact the openapi HTTP API.
//
// This is an autogenerated file, any edits which you make here will be lost!
package generated

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
	"io"
	"net/http"
	"strings"
)

// DecryptRequest defines component schema for DecryptRequest.
type DecryptRequest struct {
	CipherText     string         `json:"cipherText"`
	CipherTextKey  string         `json:"cipherTextKey"`
	LegalEntityURI LegalEntityURI `json:"legalEntityURI"`
	Nonce          string         `json:"nonce"`
}

// DecryptResponse defines component schema for DecryptResponse.
type DecryptResponse struct {
	PlainText string `json:"plainText"`
}

// EncryptRequest defines component schema for EncryptRequest.
type EncryptRequest struct {
	LegalEntityURI LegalEntityURI `json:"legalEntityURI"`
	PlainText      string         `json:"plainText"`
	PublicKey      string         `json:"publicKey"`
}

// EncryptResponse defines component schema for EncryptResponse.
type EncryptResponse struct {
	CipherText    string `json:"cipherText"`
	CipherTextKey string `json:"cipherTextKey"`
	Nonce         string `json:"nonce"`
}

// ExternalIdRequest defines component schema for ExternalIdRequest.
type ExternalIdRequest struct {
	LegalEntityURI LegalEntityURI `json:"legalEntityURI"`
	SubjectURI     SubjectURI     `json:"subjectURI"`
}

// ExternalIdResponse defines component schema for ExternalIdResponse.
type ExternalIdResponse struct {
	ExternalId string `json:"externalId"`
}

// LegalEntityURI defines component schema for LegalEntityURI.
type LegalEntityURI string

// SubjectURI defines component schema for SubjectURI.
type SubjectURI string

// Client which conforms to the OpenAPI3 specification for this service. The
// server should be fully qualified with shema and server, ie,
// https://deepmap.com.
type Client struct {
	Server string
	Client http.Client
}

// Decrypt request with JSON body
func (c *Client) Decrypt(ctx context.Context, body DecryptRequest) (*http.Response, error) {
	req, err := NewDecryptRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	return c.Client.Do(req)
}

// Encrypt request with JSON body
func (c *Client) Encrypt(ctx context.Context, body EncryptRequest) (*http.Response, error) {
	req, err := NewEncryptRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	return c.Client.Do(req)
}

// ExternalId request with JSON body
func (c *Client) ExternalId(ctx context.Context, body ExternalIdRequest) (*http.Response, error) {
	req, err := NewExternalIdRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	return c.Client.Do(req)
}

// GenerateKeyPair request
func (c *Client) GenerateKeyPair(ctx context.Context, params *GenerateKeyPairParams) (*http.Response, error) {
	req, err := NewGenerateKeyPairRequest(c.Server, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	return c.Client.Do(req)
}

// NewDecryptRequest generates requests for Decrypt with JSON body
func NewDecryptRequest(server string, body DecryptRequest) (*http.Request, error) {
	var bodyReader io.Reader

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)

	return NewDecryptRequestWithBody(server, "application/json", bodyReader)
}

// NewDecryptRequestWithBody generates requests for Decrypt with non-JSON body
func NewDecryptRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	queryURL := fmt.Sprintf("%s/crypto/decrypt", server)

	req, err := http.NewRequest("POST", queryURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	return req, nil
}

// NewEncryptRequest generates requests for Encrypt with JSON body
func NewEncryptRequest(server string, body EncryptRequest) (*http.Request, error) {
	var bodyReader io.Reader

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)

	return NewEncryptRequestWithBody(server, "application/json", bodyReader)
}

// NewEncryptRequestWithBody generates requests for Encrypt with non-JSON body
func NewEncryptRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	queryURL := fmt.Sprintf("%s/crypto/encrypt", server)

	req, err := http.NewRequest("POST", queryURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	return req, nil
}

// NewExternalIdRequest generates requests for ExternalId with JSON body
func NewExternalIdRequest(server string, body ExternalIdRequest) (*http.Request, error) {
	var bodyReader io.Reader

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)

	return NewExternalIdRequestWithBody(server, "application/json", bodyReader)
}

// NewExternalIdRequestWithBody generates requests for ExternalId with non-JSON body
func NewExternalIdRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	queryURL := fmt.Sprintf("%s/crypto/external_id", server)

	req, err := http.NewRequest("POST", queryURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	return req, nil
}

// NewGenerateKeyPairRequest generates requests for GenerateKeyPair
func NewGenerateKeyPairRequest(server string, params *GenerateKeyPairParams) (*http.Request, error) {
	var err error

	queryURL := fmt.Sprintf("%s/crypto/generate", server)

	var queryStrings []string

	var queryParam0 string

	queryParam0, err = runtime.StyleParam("form", true, "legalEntityURI", params.LegalEntityURI)
	if err != nil {
		return nil, err
	}

	queryStrings = append(queryStrings, queryParam0)

	if len(queryStrings) != 0 {
		queryURL += "?" + strings.Join(queryStrings, "&")
	}

	req, err := http.NewRequest("POST", queryURL, nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// GenerateKeyPairParams defines parameters for GenerateKeyPair.
type GenerateKeyPairParams struct {
	LegalEntityURI LegalEntityURI `json:"legalEntityURI"`
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// decrypt a cipherText for the given legalEntity (POST /crypto/decrypt)
	Decrypt(ctx echo.Context) error
	// encrypt a piece of data for the given legalEntity or public key (POST /crypto/encrypt)
	Encrypt(ctx echo.Context) error
	// calculate an externalId for an identifier for a given legalEntity (POST /crypto/external_id)
	ExternalId(ctx echo.Context) error
	// Send a request for checking if the given combination has valid consent (POST /crypto/generate)
	GenerateKeyPair(ctx echo.Context, params GenerateKeyPairParams) error
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

	// Parameter object where we will unmarshal all parameters from the
	// context.
	var params GenerateKeyPairParams
	// ------------- Required query parameter "legalEntityURI" -------------
	if paramValue := ctx.QueryParam("legalEntityURI"); paramValue != "" {

	} else {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Query argument legalEntityURI is required, but not found"))
	}

	err = runtime.BindQueryParameter("form", true, true, "legalEntityURI", ctx.QueryParams(), &params.LegalEntityURI)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter legalEntityURI: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GenerateKeyPair(ctx, params)
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

}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/7xX32/jNgz+Vwh1j0ad2x0GLG8rVgxBu61od09DMdAyE+vOllRJzuoV+d8HyXb8K26S",
	"+9E8BRZNfSQ/kp9fGFeFVpKks2z5wizPqMDw91fiptLunp5Kss4/0UZpMk5QOOdCZ2T+oudwlpLlRmgn",
	"lGRLdoWWfvoAJLlKKYWeacRcpYktmXVGyA3bRT1HN1RNfSVDXyQDLErBVkVBzggOn6k65DinDebX0glX",
	"fbxfec8/GFqzJbuIu6jjJuT4dmi9i5hUktNRQLXV5PpdxAw9lcJQypZ/j7H0o2bjFLQ3P+6irgpWK2lp",
	"Wgado5AnVSFYgjtYhRHazqnHcC3HTBjeMzwHEi4jAxlaQNBlkgt+QxUoA8MkRCCVg0S5jEWjoL62cqcn",
	"JRESTQUpOjxEoT38qaO769+71Aazwzw8RoQOa/+6Qd7nan9GC3Zt476sDWf9zTTfTPNcfUnznNgr18+O",
	"jMR8lc4Ora8lli2TT8TdCe8+dJZHKdDzOo5jrvS0t5nmOKPnfYJFStKJtSBzNMs9lx7F7SRVw1s+3q8g",
	"pbWQQm4AJSizQSn+Q38cQWlLzPMKXEbAS+tUKoINIHfKY6FnLHTu4WTOabuMY1k6eynzuIbsA41xk1ws",
	"mt8hkj0MyvEKPg/D9zg0qR4C1OgESXcqqsTKi5+b3wFYPq9CrtUU0i93K7CauFgLHvIEa2UgNJICS2Yr",
	"OFnALYock5zgX+EyIcFDaI/BagwdkwtODTMkFv7+3+5ut+99VpxwIYQ/+u+1t2jiLGJbMrbGtLh8d7nw",
	"bylNErVgS/b+cnHp49LoskC2uH45TutlFNio6vbynAyheCKy1qAmFll3pdIwS7iSzmd4+cJQ67wJP/5k",
	"PYZWdhxrqZEi2Q0J7ExJ4UHdMgH4j4vFt7+9aclw/bC+f95Ae30EiUoryFSeWkgOLOIwzXYR+zCB6Ad0",
	"HGzqRm8ZKeQWc5FCQQ7DvpoCEJIrY4g72BvYsijQVF1xAHt6LBDQt8BGbEn2F7TnNW5sGL+h+uzRu2up",
	"0Mz/eSq0Bt+HCiNJ8sZUGC/mM6gwI18B5UAmvykxGkxerQniBGpdz8pZbvg5PpQ8rzGlWSv/iPQVtnS7",
	"5zsRZqIN3poz06V+Bm36Kz1Dm70tQTjmvMzRkd/zXakCQVD2NEb95OxhsiHpyUDz/Ggtbqi6Q2HCcjJY",
	"kCPjvR7a/Q2qql3/AQ5Qi8fniD2VZIKGrDfoRJgN6RGdWOqxbNw9Tnj1bioO/DeS/2ZKiCRwQxiGRMk5",
	"Wbsu87w6r+arpuaNwtwDPyBWhjjaF82+T/pUeCCZAraHtX7JiH/2WRbr3rjgqvDfVkHl+LBqp9znICit",
	"KR92u/8DAAD//yH+BcKOEAAA",
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file.
func GetSwagger() (*openapi3.Swagger, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	swagger, err := openapi3.NewSwaggerLoader().LoadSwaggerFromData(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error loading Swagger: %s", err)
	}
	return swagger, nil
}

