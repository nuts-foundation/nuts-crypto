/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
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
 *
 */

package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// ErrNotImplemented indicates that this client API call is not implemented.
var ErrNotImplemented = errors.New("operation not implemented")

// HttpClient holds the server address and other basic settings for the http client
type HttpClient struct {
	ServerAddress string
	Timeout       time.Duration
}

func (hb HttpClient) clientWithRequestEditor(fn RequestEditorFn) ClientInterface {
	url := hb.ServerAddress
	if !strings.Contains(url, "http") {
		url = fmt.Sprintf("http://%v", hb.ServerAddress)
	}

	response, err := NewClientWithResponses(url, WithRequestEditorFn(fn))
	if err != nil {
		panic(err)
	}
	return response
}

func (hb HttpClient) client() ClientInterface {
	return hb.clientWithRequestEditor(nil)
}

func (hb HttpClient) GenerateVendorCACSR(name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	response, err := hb.client().GenerateVendorCACSR(ctx, &GenerateVendorCACSRParams{Name: name})
	if err != nil {
		return nil, err
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	responseData, err := readResponse(response)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(responseData)
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("returned PEM is not a CERTIFICATE REQUEST")
	}
	return block.Bytes, nil
}

func (hb HttpClient) GenerateKeyPair(key types.KeyIdentifier) (crypto.PublicKey, error) {
	if key.Qualifier() != "" {
		// API doesn't define 'qualifier' parameter so make sure the caller isn't providing one which would lead
		// to unexpected results (e.g. overwriting wrong key).
		return nil, errors.New("API only support GenerateKeyPair() without qualifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	response, err := hb.client().GenerateKeyPair(ctx, &GenerateKeyPairParams{LegalEntity: Identifier(key.Owner())})
	if err != nil {
		return nil, err
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	responseData, err := readResponse(response)
	if err != nil {
		return nil, err
	}
	return cert.PemToPublicKey(responseData)
}

func (hb HttpClient) GetPublicKeyAsJWK(key types.KeyIdentifier) (jwk.Key, error) {
	if key.Qualifier() != "" {
		// API doesn't define 'qualifier' parameter so make sure the caller isn't providing one which would lead
		// to unexpected results (e.g. retrieving wrong key).
		return nil, errors.New("API only support GetPublicKeyAsJWK() without qualifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	httpClient := hb.clientWithRequestEditor(func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Accept", "application/json")
		return nil
	})
	response, err := httpClient.PublicKey(ctx, key.Owner())
	if err != nil {
		return nil, err
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	jwkSet, err := jwk.Parse(response.Body)
	if err != nil {
		return nil, err
	}
	return jwkSet.Keys[0], nil
}

func readResponse(response *http.Response) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(response.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func testResponseCode(expectedStatusCode int, response *http.Response) error {
	if response.StatusCode != expectedStatusCode {
		responseData, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("server returned HTTP %d (expected: %d), response: %s",
			response.StatusCode, expectedStatusCode, string(responseData))
	}
	return nil
}

func (hb HttpClient) GetPublicKeyAsPEM(key types.KeyIdentifier) (string, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) DecryptKeyAndCipherText(cipherText types.DoubleEncryptedCipherText, key types.KeyIdentifier) ([]byte, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) EncryptKeyAndPlainText(plainText []byte, keys []jwk.Key) (types.DoubleEncryptedCipherText, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) CalculateExternalId(subject string, actor string, key types.KeyIdentifier) ([]byte, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) Sign(data []byte, key types.KeyIdentifier) ([]byte, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) SignCertificate(subjectKey types.KeyIdentifier, caKey types.KeyIdentifier, pkcs10 []byte, profile pkg.CertificateProfile) ([]byte, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) GetPrivateKey(key types.KeyIdentifier) (crypto.Signer, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) VerifyWith(data []byte, sig []byte, jwk jwk.Key) (bool, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) GetTLSCertificate(caKey types.KeyIdentifier) (*x509.Certificate, crypto.PrivateKey, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) SignJWT(claims map[string]interface{}, key types.KeyIdentifier) (string, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) SignJWSEphemeral(payload []byte, caKey types.KeyIdentifier, csr x509.CertificateRequest, signingTime time.Time) ([]byte, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) VerifyJWS(signature []byte, signingTime time.Time, certVerifier cert.Verifier) ([]byte, error) {
	panic(ErrNotImplemented)
}

func (hb HttpClient) PrivateKeyExists(key types.KeyIdentifier) bool {
	panic(ErrNotImplemented)
}

func (hb HttpClient) TrustStore() cert.TrustStore {
	panic(ErrNotImplemented)
}
