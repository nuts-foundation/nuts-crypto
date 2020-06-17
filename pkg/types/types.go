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

// types and interfaces used by all other packages
package types

import (
	"fmt"
)

// --storage config flag
const ConfigStorage string = "storage"

// default setting for --storage "fs"
const ConfigStorageFs string = "fs"

// --fspath config flag
const ConfigFSPath string = "fspath"

// default setting for --fspath "./"
const ConfigFSPathDefault string = "./"

// --keysize config flag
const ConfigKeySize string = "keysize"

// default setting for --keysize "2048"
const ConfigKeySizeDefault int = 2048

// type identifying the legalEntity responsible for the Patient/medical data
type LegalEntity struct {
	URI string
}

// KeyIdentifier is the reference to a key pair
type KeyIdentifier interface {
	// String returns a human readable representation for this KeyIdentifier
	String() string
	// Owner returns the identifier of the entity owning this key pair (e.g. LegalEntity, person, organization, etc). The
	// owner must uniquely identify this entity (in other words, multiple entities must not share the same identifier).
	Owner() string
	// Qualifier returns the identifier which points to a key pair for this owner. It must be unique for this owner (but
	// other owners can have key pairs with the same qualifier).
	Qualifier() string
	// WithQualifier returns a new KeyIdentifier with the specified qualifier.
	WithQualifier(qualifier string) KeyIdentifier
}

type entityKeyIdentifier struct {
	entity    LegalEntity
	qualifier string
}

// WithQualifier: see KeyIdentifier interface
func (e entityKeyIdentifier) WithQualifier(qualifier string) KeyIdentifier {
	return &entityKeyIdentifier{
		entity:    e.entity,
		qualifier: qualifier,
	}
}

// String: see KeyIdentifier interface
func (e entityKeyIdentifier) String() string {
	return fmt.Sprintf("[%s|%s]", e.entity.URI, e.qualifier)
}

// Owner: see KeyIdentifier interface
func (e entityKeyIdentifier) Owner() string {
	return e.entity.URI
}

// Qualifier: see KeyIdentifier interface
func (e entityKeyIdentifier) Qualifier() string {
	return e.qualifier
}

// KeyForEntity returns a KeyIdentifier for the given LegalEntity. The KeyIdentifier will not have a qualifier.
func KeyForEntity(entity LegalEntity) KeyIdentifier {
	return entityKeyIdentifier{
		entity: entity,
	}
}

// Struct defining the encrypted data in CipherText, an encrypted symmetric key in CipherTextKeys (1 for each given public key) and the nonce needed for the AES_GCM decryption.
type DoubleEncryptedCipherText struct {
	CipherText     []byte
	CipherTextKeys [][]byte
	Nonce          []byte
}
