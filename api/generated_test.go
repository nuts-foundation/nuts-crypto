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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/nuts-go-core/mock"
)

type testServerInterface struct {
	err error
}

func (t *testServerInterface) SelfSignVendorCACertificate(ctx echo.Context, params SelfSignVendorCACertificateParams) error {
	return t.err
}

func (t *testServerInterface) GenerateVendorCACSR(ctx echo.Context, params GenerateVendorCACSRParams) error {
	return t.err
}

func (t *testServerInterface) Decrypt(ctx echo.Context) error {
	return t.err
}

func (t *testServerInterface) Encrypt(ctx echo.Context) error {
	return t.err
}

func (t *testServerInterface) ExternalId(ctx echo.Context) error {
	return t.err
}

func (t *testServerInterface) GenerateKeyPair(ctx echo.Context, params GenerateKeyPairParams) error {
	return t.err
}

func (t *testServerInterface) Sign(ctx echo.Context) error {
	return t.err
}

func (t *testServerInterface) Verify(ctx echo.Context) error {
	return t.err
}

func (t *testServerInterface) PublicKey(ctx echo.Context, urn string) error {
	return t.err
}

func (t *testServerInterface) SignJwt(ctx echo.Context) error {
	return t.err
}

var siws = []*ServerInterfaceWrapper{
	serverInterfaceWrapper(nil), serverInterfaceWrapper(errors.New("Server error")),
}

func TestServerInterfaceWrapper_Decrypt(t *testing.T) {
	for _, siw := range siws {
		t.Run("Decrypt call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.POST, "/?", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			err := siw.Decrypt(c)
			tsi := siw.Handler.(*testServerInterface)
			assert.Equal(t, tsi.err, err)
		})
	}
}

func TestServerInterfaceWrapper_Encrypt(t *testing.T) {
	for _, siw := range siws {
		t.Run("Encrypt call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.POST, "/?", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			err := siw.Encrypt(c)
			tsi := siw.Handler.(*testServerInterface)
			assert.Equal(t, tsi.err, err)
		})
	}
}

func TestServerInterfaceWrapper_ExternalId(t *testing.T) {
	for _, siw := range siws {
		t.Run("Encrypt call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.POST, "/?", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			err := siw.ExternalId(c)
			tsi := siw.Handler.(*testServerInterface)
			assert.Equal(t, tsi.err, err)
		})
	}
}

func TestServerInterfaceWrapper_PublicKey(t *testing.T) {
	for _, siw := range siws {
		t.Run("Encrypt call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.GET, "/", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)
			c.SetParamNames("urn")
			c.SetParamValues("le")

			err := siw.PublicKey(c)
			tsi := siw.Handler.(*testServerInterface)
			assert.Equal(t, tsi.err, err)
		})
	}
}

func TestServerInterfaceWrapper_SignJwt(t *testing.T) {
	for _, siw := range siws {
		t.Run("Encrypt call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.GET, "/", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			err := siw.SignJwt(c)
			tsi := siw.Handler.(*testServerInterface)
			assert.Equal(t, tsi.err, err)
		})
	}
}

func TestServerInterfaceWrapper_GenerateKeyPair(t *testing.T) {
	t.Run("GenerateKeyPairAPI call returns no error", func(t *testing.T) {
		// given
		siw := serverInterfaceWrapper(nil)
		q := make(url.Values)
		q.Set("legalEntity", "le")
		req := httptest.NewRequest(echo.POST, "/?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)

		// then
		if err := siw.GenerateKeyPair(c); err != nil {
			t.Errorf("Got err during call: %s", err.Error())
		}

		if rec.Code != http.StatusOK {
			t.Errorf("Got status=%d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("Missing legalEntity returns 400", func(t *testing.T) {
		// given
		siw := serverInterfaceWrapper(nil)
		req := httptest.NewRequest(echo.POST, "/", nil)
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)

		// then
		if err := siw.GenerateKeyPair(c); err != nil {
			httpError := err.(*echo.HTTPError)
			if httpError.Code != http.StatusBadRequest {
				t.Errorf("Got status=%d, want %d", rec.Code, http.StatusBadRequest)
			}
		} else {
			t.Errorf("Expected error for bad request")
		}
	})

	t.Run("Server error is returned", func(t *testing.T) {
		// given
		siw := serverInterfaceWrapper(errors.New("Server error"))
		q := make(url.Values)
		q.Set("legalEntity", "le")
		req := httptest.NewRequest(echo.POST, "/?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)

		// then
		if err := siw.GenerateKeyPair(c); err != nil {
			expected := "Server error"
			if err.Error() != expected {
				t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
			}
		} else {
			t.Errorf("Expected error for bad request")
		}
	})
}

func TestServerInterfaceWrapper_Sign(t *testing.T) {
	for _, siw := range siws {
		t.Run("Sign call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.POST, "/?", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			// then
			err := siw.Sign(c)
			tsi := siw.Handler.(*testServerInterface)
			if tsi.err != err {
				t.Errorf("Expected argument doesn't match given err %v <> %v", tsi.err, err)
			}
		})
	}
}

func TestServerInterfaceWrapper_Verify(t *testing.T) {
	for _, siw := range siws {
		t.Run("Verify call returns expected error", func(t *testing.T) {
			req := httptest.NewRequest(echo.POST, "/?", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			err := siw.Verify(c)
			tsi := siw.Handler.(*testServerInterface)
			if tsi.err != err {
				t.Errorf("Expected argument doesn't match given err %v <> %v", tsi.err, err)
			}
		})
	}
}

func TestRegisterHandlers(t *testing.T) {
	t.Run("Registers routes for crypto module", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockEchoRouter(ctrl)

		echo.EXPECT().POST("/crypto/csr/vendorca", gomock.Any())
		echo.EXPECT().POST("/crypto/certificate/vendorca", gomock.Any())
		echo.EXPECT().POST("/crypto/decrypt", gomock.Any())
		echo.EXPECT().POST("/crypto/encrypt", gomock.Any())
		echo.EXPECT().POST("/crypto/external_id", gomock.Any())
		echo.EXPECT().POST("/crypto/generate", gomock.Any())
		echo.EXPECT().POST("/crypto/sign", gomock.Any())
		echo.EXPECT().POST("/crypto/verify", gomock.Any())
		echo.EXPECT().POST("/crypto/sign_jwt", gomock.Any())
		echo.EXPECT().GET("/crypto/public_key/:urn", gomock.Any())

		RegisterHandlers(echo, &testServerInterface{})
	})
}

func serverInterfaceWrapper(err error) *ServerInterfaceWrapper {
	return &ServerInterfaceWrapper{
		Handler: &testServerInterface{err: err},
	}
}
