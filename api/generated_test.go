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
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type testServerInterface struct {
	err error
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

func TestServerInterfaceWrapper_GenerateKeyPair(t *testing.T) {
	t.Run("GenerateKeyPairAPI call returns 201 CREATED", func(t *testing.T) {
		// given
		siw := serverInterfaceWrapper(nil)
		e := echo.New()
		e.POST("/crypto/generate", siw.GenerateKeyPair)

		// when
		q := make(url.Values)
		q.Set("legalEntity", "le")
		req := httptest.NewRequest(echo.POST, "/?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/crypto/generate")

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
		e := echo.New()
		e.POST("/crypto/generate", siw.GenerateKeyPair)

		// when
		req := httptest.NewRequest(echo.POST, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/crypto/generate")

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
		e := echo.New()
		e.POST("/crypto/generate", siw.GenerateKeyPair)

		// when
		q := make(url.Values)
		q.Set("legalEntity", "le")
		req := httptest.NewRequest(echo.POST, "/?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/crypto/generate")

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

func serverInterfaceWrapper(err error) *ServerInterfaceWrapper {
	return &ServerInterfaceWrapper{
		Handler: &testServerInterface{err: err},
	}
}
