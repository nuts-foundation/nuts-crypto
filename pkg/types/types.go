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

// ConfigSignatureFormat defines --signature config flag
const ConfigSignatureFormat = "signature"

// ConfigSignatureFormatDefault holds the default value for ConfigSignatureFormat
const ConfigSignatureFormatDefault = SignatureFormatPlainRSA

const (
	SignatureFormatPlainRSA = "plain-rsa"
	SignatureFormatJWS      = "jws"
)

// type identifying the legalEntity responsible for the Patient/medical data
type LegalEntity struct {
	URI string
}

// Struct defining the encrypted data in CipherText, an encrypted symmetric key in CipherTextKeys (1 for each given public key) and the nonce needed for the AES_GCM decryption.
type DoubleEncryptedCipherText struct {
	CipherText     []byte
	CipherTextKeys [][]byte
	Nonce          []byte
}
