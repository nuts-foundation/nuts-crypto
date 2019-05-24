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

package engine

import (
	types "github.com/nuts-foundation/nuts-crypto/pkg"
)

// CryptoClient defines the functions than can be called by a Cmd, Direct or via rest call.
type CryptoClient interface {
	// decrypt a cipherText for the given legalEntity
	DecryptKeyAndCipherTextFor(cipherText types.DoubleEncryptedCipherText, legalEntity types.LegalEntity) ([]byte, error)
	// EncryptKeyAndPlainTextFor encrypts a piece of data for the given PEM encoded public key
	EncryptKeyAndPlainTextWith(plainText []byte, pemKey []string) (types.DoubleEncryptedCipherText, error)
	// ExternalIdFor calculates an externalId for an identifier for a given legalEntity
	ExternalIdFor(data []byte, entity types.LegalEntity) ([]byte, error)
	// GenerateKeyPairFor creates a KeyPair on the backend for given legalEntity
	GenerateKeyPairFor(legalEntity types.LegalEntity) error
	// SignFor signs a piece of data for a legal entity
	SignFor(data []byte, legalEntity types.LegalEntity) ([]byte, error)
	// VerifyWith verifies a signature for a given PEM encoded public key
	VerifyWith(data []byte, sig []byte, pemKey string) (bool, error)
	// PublicKey returns the PEM encoded PublicKey for a given legal entity
	PublicKey(legalEntity types.LegalEntity) (string, error)
}

// NewCryptoClient returns a CryptoClient which either resolves call directly to the engine or uses a REST client.
func NewCryptoClient() CryptoClient {
	// todo: use configuration to choose client
	return NewCryptoEngine()
}