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
 */

package jwx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	rsa2 "crypto/rsa"
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestSignJWT(t *testing.T) {
	claims := map[string]interface{}{"iss": "nuts"}
	t.Run("creates valid JWT using rsa keys", func(t *testing.T) {
		key, _ := rsa2.GenerateKey(rand.Reader, 2048)
		tokenString, err := SignJWT(key, claims)

		assert.Nil(t, err)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return key.Public(), nil
		})

		assert.True(t, token.Valid)
		assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
	})

	t.Run("creates valid JWT using ec keys", func(t *testing.T) {
		p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

		keys := []*ecdsa.PrivateKey{p256, p384, p521}

		for _, key := range keys {
			name := fmt.Sprintf("using %s", key.Params().Name)
			t.Run(name, func(t *testing.T) {
				tokenString, err := SignJWT(key, claims)

				if assert.Nil(t, err) {
					token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
						return key.Public(), nil
					})

					if assert.Nil(t, err) {
						assert.True(t, token.Valid)
						assert.Equal(t, "nuts", token.Claims.(jwt.MapClaims)["iss"])
					}
				}
			})
		}
	})

	t.Run("returns error on unknown curve", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		_, err := SignJWT(key, claims)

		assert.NotNil(t, err)
	})

	t.Run("returns error on unsupported crypto", func(t *testing.T) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		_, err := SignJWT(key, claims)

		assert.NotNil(t, err)
	})
}
