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
	"errors"
	"time"

	"github.com/nuts-foundation/nuts-crypto/pkg/types"
)

// Storage interface containing functions for storing and retrieving keys
type Storage interface {
	GetPrivateKey(key types.KeyIdentifier) (*rsa.PrivateKey, error)
	GetPublicKey(key types.KeyIdentifier) (*rsa.PublicKey, error)
	PrivateKeyExists(key types.KeyIdentifier) bool
	SavePrivateKey(keyIdentifier types.KeyIdentifier, key *rsa.PrivateKey) error
	SaveCertificate(key types.KeyIdentifier, certificate []byte) error
	GetCertificate(key types.KeyIdentifier) (*x509.Certificate, error)
	CertificateExists(key types.KeyIdentifier) bool
	// GetExpiringCertificates lists all certificates that will expire between given times.
	// Till must be > from, otherwise an error is returned.
	GetExpiringCertificates(from time.Time, till time.Time) ([]*x509.Certificate, error)
}

// shared function to convert bytes to a RSA private key
func bytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, errors.New("malformed PEM block")
	}
	b := block.Bytes
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}
