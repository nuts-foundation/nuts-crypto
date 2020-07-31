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
	"crypto/x509"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type handler struct {
	statusCode   int
	responseData []byte
}

func (h handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	writer.WriteHeader(h.statusCode)
	writer.Write(h.responseData)
}

var genericError = []byte("failed")

func TestHttpClient_GenerateVendorCACSR(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		csrBytes, _ := ioutil.ReadFile("../test/csr.pem")
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: csrBytes})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GenerateVendorCACSR("Vendor")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, res)
	})
	t.Run("error - server returned non-CSR PEM", func(t *testing.T) {
		csrBytes, _ := ioutil.ReadFile("../test/publickey.pem")
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: csrBytes})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GenerateVendorCACSR("Vendor")
		assert.EqualError(t, err, "returned PEM is not a CERTIFICATE REQUEST")
		assert.Nil(t, res)
	})
	t.Run("error - response not HTTP OK", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: genericError})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GenerateVendorCACSR("Vendor")
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200), response: failed")
		assert.Nil(t, res)
	})
	t.Run("error - server not running", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK})
		s.Close()
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GenerateVendorCACSR("Vendor")
		assert.Contains(t, err.Error(), "connection refused")
		assert.Nil(t, res)
	})
}

func TestHttpClient_GenerateKeyPair(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		csrBytes, _ := ioutil.ReadFile("../test/publickey.pem")
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: csrBytes})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: "foo"}))
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, res)
	})
	t.Run("error - qualifier specified", func(t *testing.T) {
		c := HttpClient{ServerAddress: "foo", Timeout: time.Second}
		res, err := c.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: "foo"}).WithQualifier("unexpected"))
		assert.EqualError(t, err, "API only support GenerateKeyPair() without qualifier")
		assert.Nil(t, res)
	})
	t.Run("error - server returned non-Public Key PEM", func(t *testing.T) {
		csrBytes, _ := ioutil.ReadFile("../test/truststore.pem")
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: csrBytes})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: "foo"}))
		assert.EqualError(t, err, "failed to decode PEM block containing public key, key is of the wrong type")
		assert.Nil(t, res)
	})
	t.Run("error - response not HTTP OK", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: genericError})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: "foo"}))
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200), response: failed")
		assert.Nil(t, res)
	})
	t.Run("error - server not running", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK})
		s.Close()
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: "foo"}))
		assert.Contains(t, err.Error(), "connection refused")
		assert.Nil(t, res)
	})
}

func TestHttpClient_GetPublicKeyAsJWK(t *testing.T) {
	jwkAsString := `
{
  "kty" : "RSA",
  "n"   : "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
  "e"   : "AQAB"
}`
	jwkAsBytes := []byte(jwkAsString)
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: jwkAsBytes})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GetPublicKeyAsJWK(types.KeyForEntity(types.LegalEntity{URI: "foo"}))
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, res)
	})
	t.Run("error - qualifier specified", func(t *testing.T) {
		c := HttpClient{ServerAddress: "foo", Timeout: time.Second}
		res, err := c.GetPublicKeyAsJWK(types.KeyForEntity(types.LegalEntity{URI: "foo"}).WithQualifier("unexpected"))
		assert.EqualError(t, err, "API only support GetPublicKeyAsJWK() without qualifier")
		assert.Nil(t, res)
	})
	t.Run("error - server returned non-JWK", func(t *testing.T) {
		csrBytes, _ := ioutil.ReadFile("../test/truststore.pem")
		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: csrBytes})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GetPublicKeyAsJWK(types.KeyForEntity(types.LegalEntity{URI: "foo"}))
		assert.EqualError(t, err, "failed to unmarshal JWK: invalid character '-' in numeric literal")
		assert.Nil(t, res)
	})
	t.Run("error - response not HTTP OK", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: genericError})
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GetPublicKeyAsJWK(types.KeyForEntity(types.LegalEntity{URI: "foo"}))
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200), response: failed")
		assert.Nil(t, res)
	})
	t.Run("error - server not running", func(t *testing.T) {
		s := httptest.NewServer(handler{statusCode: http.StatusOK})
		s.Close()
		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
		res, err := c.GetPublicKeyAsJWK(types.KeyForEntity(types.LegalEntity{URI: "foo"}))
		assert.Contains(t, err.Error(), "connection refused")
		assert.Nil(t, res)
	})
}

func TestHttpClient_NonImplemented(t *testing.T) {
	c := HttpClient{ServerAddress: "foo", Timeout: time.Second}

	funcs := map[string]func(){
		"GetPublicKeyAsPEM": func() {
			c.GetPublicKeyAsPEM(nil)
		},
		"DecryptKeyAndCipherText": func() {
			c.DecryptKeyAndCipherText(types.DoubleEncryptedCipherText{}, nil)
		},
		"EncryptKeyAndPlainText": func() {
			c.EncryptKeyAndPlainText(nil, nil)
		},
		"CalculateExternalId": func() {
			c.CalculateExternalId("", "", nil)
		},
		"Sign": func() {
			c.Sign(nil, nil)
		},
		"SignCertificate": func() {
			c.SignCertificate(nil, nil, nil, pkg.CertificateProfile{})
		},
		"GetPrivateKey": func() {
			c.GetPrivateKey(nil)
		},
		"VerifyWith": func() {
			c.VerifyWith(nil, nil, nil)
		},
		"GetTLSCertificate": func() {
			c.GetTLSCertificate(types.LegalEntity{})
		},
		"RenewTLSCertificate": func() {
			c.RenewTLSCertificate(types.LegalEntity{})
		},
		"GetSigningCertificate": func() {
			c.GetSigningCertificate(types.LegalEntity{})
		},
		"RenewSigningCertificate": func() {
			c.RenewSigningCertificate(types.LegalEntity{})
		},
		"SignJWT": func() {
			c.SignJWT(nil, nil)
		},
		"SignJWSEphemeral": func() {
			c.SignJWSEphemeral(nil, nil, x509.CertificateRequest{}, time.Now())
		},
		"SignJWS": func() {
			c.SignJWS(nil, nil)
		},
		"VerifyJWS": func() {
			c.VerifyJWS(nil, time.Now(), nil)
		},
		"PrivateKeyExists": func() {
			c.PrivateKeyExists(nil)
		},
		"TrustStore": func() {
			c.TrustStore()
		},
		"StoreVendorCACertificate": func() {
			c.StoreVendorCACertificate(nil)
		},
	}
	for fnName, fn := range funcs {
		t.Run(fnName+" should panic", func(t *testing.T) {
			assert.PanicsWithValue(t, ErrNotImplemented, func() {
				fn()
			})
		})
	}
}

//
//func TestHttpClient_SearchOrganizations(t *testing.T) {
//	t.Run("200", func(t *testing.T) {
//		org, _ := json.Marshal(organizations)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: org})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		res, err := c.SearchOrganizations("query")
//
//		if assert.Nil(t, err) {
//			assert.Equal(t, 2, len(res))
//		}
//	})
//}
//
//func TestHttpClient_ReverseLookup(t *testing.T) {
//	t.Run("200", func(t *testing.T) {
//		org, _ := json.Marshal(organizations[0:1])
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: org})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		res, err := c.ReverseLookup("name")
//
//		if assert.Nil(t, err) {
//			assert.Equal(t, organizations[0], *res)
//		}
//	})
//
//	t.Run("404", func(t *testing.T) {
//		s := httptest.NewServer(handler{statusCode: http.StatusNotFound})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		_, err := c.ReverseLookup("name")
//
//		if assert.NotNil(t, err) {
//			assert.True(t, errors.Is(err, ErrOrganizationNotFound))
//		}
//	})
//
//	t.Run("too many results", func(t *testing.T) {
//		org, _ := json.Marshal(organizations)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: org})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		_, err := c.ReverseLookup("name")
//
//		if assert.NotNil(t, err) {
//			assert.True(t, errors.Is(err, ErrOrganizationNotFound))
//		}
//	})
//}
//
//func TestHttpClient_VendorClaim(t *testing.T) {
//	t.Run("ok", func(t *testing.T) {
//		event := events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{}, nil)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: event.Marshal()})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		key := map[string]interface{}{
//			"e": 12345,
//		}
//		event, err := c.VendorClaim( "orgID", "name", []interface{}{key})
//		if !assert.NoError(t, err) {
//			return
//		}
//		assert.NotNil(t, event)
//	})
//	t.Run("error 500", func(t *testing.T) {
//		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: []byte{}})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		event, err := c.VendorClaim("orgID", "name", []interface{}{})
//		assert.EqualError(t, err, "registry returned HTTP 500 (expected: 200), response: ", "error")
//		assert.Nil(t, event)
//	})
//}
//
//func TestHttpClient_RegisterVendor(t *testing.T) {
//	t.Run("ok", func(t *testing.T) {
//		event := events.CreateEvent(domain.RegisterVendor, domain.RegisterVendorEvent{}, nil)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: event.Marshal()})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		vendor, err := c.RegisterVendor("name", "")
//		if !assert.NoError(t, err) {
//			return
//		}
//		assert.NotNil(t, vendor)
//	})
//	t.Run("error 500", func(t *testing.T) {
//		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: []byte{}})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		event, err := c.RegisterVendor("name", "")
//		assert.EqualError(t, err, "registry returned HTTP 500 (expected: 200), response: ", "error")
//		assert.Nil(t, event)
//	})
//}
//
//func TestHttpClient_RefreshVendorCertificate(t *testing.T) {
//	t.Run("ok", func(t *testing.T) {
//		event := events.CreateEvent(domain.RegisterVendor, domain.RegisterVendorEvent{}, nil)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: event.Marshal()})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		event, err := c.RefreshVendorCertificate()
//		if !assert.NoError(t, err) {
//			return
//		}
//		assert.NotNil(t, event)
//	})
//	t.Run("error 500", func(t *testing.T) {
//		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: []byte{}})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		event, err := c.RefreshVendorCertificate()
//		assert.EqualError(t, err, "registry returned HTTP 500 (expected: 200), response: ", "error")
//		assert.Nil(t, event)
//	})
//}
//
//func TestHttpClient_RefreshOrganizationCertificate(t *testing.T) {
//	t.Run("ok", func(t *testing.T) {
//		event := events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{}, nil)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: event.Marshal()})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		event, err := c.RefreshOrganizationCertificate("1234")
//		if !assert.NoError(t, err) {
//			return
//		}
//		assert.NotNil(t, event)
//	})
//	t.Run("error 500", func(t *testing.T) {
//		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: []byte{}})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		event, err := c.RefreshOrganizationCertificate("1234")
//		assert.EqualError(t, err, "registry returned HTTP 500 (expected: 200), response: ", "error")
//		assert.Nil(t, event)
//	})
//}
//
//func TestHttpClient_RegisterEndpoint(t *testing.T) {
//	t.Run("ok", func(t *testing.T) {
//		event := events.CreateEvent(domain.RegisterEndpoint, domain.RegisterEndpointEvent{}, nil)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: event.Marshal()})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		event, err := c.RegisterEndpoint("orgId", "id", "url", "type", "status", map[string]string{"foo": "bar"})
//		if !assert.NoError(t, err) {
//			return
//		}
//		assert.NotNil(t, event)
//	})
//	t.Run("error 500", func(t *testing.T) {
//		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: []byte{}})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		event, err := c.RegisterEndpoint("orgId", "id", "url", "type", "status", nil)
//		assert.EqualError(t, err, "registry returned HTTP 500 (expected: 200), response: ", "error")
//		assert.Nil(t, event)
//	})
//}
//
//func TestHttpClient_Verify(t *testing.T) {
//	t.Run("ok", func(t *testing.T) {
//		response := altVerifyResponse{Fix: false, Events: []events.Event{
//			events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{}, nil),
//			events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{}, nil),
//			events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{}, nil),
//		}}
//		responseData, _ := json.Marshal(response)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: responseData})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//		evts, fix, err := c.Verify(true)
//		assert.NoError(t, err)
//		assert.False(t, fix)
//		assert.Len(t, evts, 3)
//	})
//	t.Run("error - http status 500", func(t *testing.T) {
//		s := httptest.NewServer(handler{statusCode: http.StatusInternalServerError, responseData: []byte{}})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		evts, fix, err := c.Verify(true)
//		assert.EqualError(t, err, "registry returned HTTP 500 (expected: 200), response: ", "error")
//		assert.Nil(t, evts)
//		assert.False(t, fix)
//	})
//	t.Run("error - invalid response", func(t *testing.T) {
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: []byte("foobar")})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		evts, fix, err := c.Verify(true)
//		assert.EqualError(t, err, "invalid character 'o' in literal false (expecting 'a')")
//		assert.Nil(t, evts)
//		assert.False(t, fix)
//	})
//}
//
//func TestHttpClient_EndpointsByOrganizationAndType(t *testing.T) {
//	t.Run("200", func(t *testing.T) {
//		eps, _ := json.Marshal(endpoints)
//		s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: eps})
//		c := HttpClient{ServerAddress: s.URL, Timeout: time.Second}
//
//		res, err := c.EndpointsByOrganizationAndType("entity", nil)
//
//		if err != nil {
//			t.Errorf("Expected no error, got [%s]", err.Error())
//		}
//
//		if len(res) != 1 {
//			t.Errorf("Expected 1 Endpoint in return, got [%d]", len(res))
//		}
//	})
//}
