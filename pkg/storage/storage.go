/*
 * Nuts crypto
 * Copyright (C) 2019 Nuts community
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

// The backend package contains the various options for storing the actual private keys.
// Currently only a file backend is supported
package storage

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
)

// Storage interface containing functions for storing and retrieving keys
type Storage interface {
	GetPrivateKey(legalEntity types.LegalEntity) (*rsa.PrivateKey, error)
	GetPublicKey(legalEntity types.LegalEntity) (*rsa.PublicKey, error)
	SavePrivateKey(legalEntity types.LegalEntity, key *rsa.PrivateKey) error
	SaveCertificate(entity types.LegalEntity, certificate []byte) error
	GetCertificate(entity types.LegalEntity) (*x509.Certificate, error)
}

// shared function to convert bytes to a RSA private key
func bytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	b := block.Bytes
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}
