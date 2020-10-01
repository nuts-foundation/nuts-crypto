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
// jwx contains functionality for signing, validating JWT's and other jwx related logic
package jwx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/dgrijalva/jwt-go"
)

var ErrUnsupportedSigningKey = errors.New("signing key algorithm not supported")

// move to crypto
func SignJWT(signer crypto.Signer, claims map[string]interface{}) (sig string, err error) {
	c := jwt.MapClaims{}
	for k, v := range claims {
		c[k] = v
	}

	// the current version of the used JWT lib doesn't support the crypto.Signer interface. The 4.0.0 version will.
	switch signer.(type) {
	case *rsa.PrivateKey:
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		sig, err = token.SignedString(signer.(*rsa.PrivateKey))
	case *ecdsa.PrivateKey:
		key := signer.(*ecdsa.PrivateKey)
		var method *jwt.SigningMethodECDSA
		if method, err = ecSigningMethod(key); err != nil {
			return
		}
		token := jwt.NewWithClaims(method, c)
		sig, err = token.SignedString(signer.(*ecdsa.PrivateKey))
	default:
		err = errors.New("unsupported signing private key")
	}

	return
}

func ecSigningMethod(key *ecdsa.PrivateKey) (method *jwt.SigningMethodECDSA, err error) {
	switch key.Params().BitSize {
	case 256:
		method = jwt.SigningMethodES256
	case 384:
		method = jwt.SigningMethodES384
	case 521:
		method = jwt.SigningMethodES512
	default:
		err = ErrUnsupportedSigningKey
	}
	return
}
