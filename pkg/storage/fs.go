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

package storage

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"io/ioutil"
	"os"
)

const privateKeyFilePostfix = "private.pem"
const certificateFilePostfix = "certificate.pem"

type FileOpenError struct {
	filePath    string
	legalEntity string
	err         error
}

// ErrNotFound indicates that the specified crypto storage entry couldn't be found.
var ErrNotFound = errors.New("entry not found")

// Error returns the string representation
func (f *FileOpenError) Error() string {
	return fmt.Sprintf("could not open entry for legalEntity: %v with filename %s: %v", f.legalEntity, f.filePath, f.err)
}

// UnWrap is needed for FileOpenError to be UnWrapped
func (f *FileOpenError) Unwrap() error {
	return f.err
}

type fileSystemBackend struct {
	fspath string
}

// Create a new filesystem backend, all directories will be created for the given path
// Using a filesystem backend in production is not recommended!
func NewFileSystemBackend(fspath string) (*fileSystemBackend, error) {
	fsc := &fileSystemBackend{
		fspath,
	}

	err := fsc.createDirs()

	if err != nil {
		return nil, err
	}

	return fsc, nil
}

func (fsc *fileSystemBackend) KeyExistsFor(entity types.LegalEntity) bool {
	_, err := os.Stat(fsc.getEntryPath(entity, privateKeyFilePostfix))
	return err == nil
}

func (fsc *fileSystemBackend) SaveCertificate(entity types.LegalEntity, certificate []byte) error {
	filenamePath := fsc.getEntryPath(entity, certificateFilePostfix)
	outFile, err := os.Create(filenamePath)
	if err != nil {
		return err
	}
	defer outFile.Close()
	var privateKey = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	}
	return pem.Encode(outFile, privateKey)
}

func (fsc *fileSystemBackend) GetCertificate(entity types.LegalEntity) (*x509.Certificate, error) {
	rawData, err := fsc.readEntry(entity, certificateFilePostfix)
	if err != nil {
		return nil, err
	}
	asn1bytes, rest := pem.Decode(rawData)
	if len(rest) > 0 {
		return nil, fmt.Errorf("found %d rest bytes after decoding PEM", len(rest))
	}
	return x509.ParseCertificate(asn1bytes.Bytes)
}

// Load the privatekey for the given legalEntity from disk. Since a legalEntity has a URI as identifier, the URI is base64 encoded and postfixed with '_private.pem'. Keys are stored in pem format and are 2k RSA keys.
func (fsc *fileSystemBackend) GetPrivateKey(legalEntity types.LegalEntity) (*rsa.PrivateKey, error) {
	data, err := fsc.readEntry(legalEntity, privateKeyFilePostfix)
	if err != nil {
		return nil, err
	}

	var key *rsa.PrivateKey
	key, err = bytesToPrivateKey(data)

	if err != nil {
		return nil, err
	}

	return key, nil
}

// Load the public key from disk, it load the private key and extract the public key from it.
func (fsc *fileSystemBackend) GetPublicKey(legalEntity types.LegalEntity) (*rsa.PublicKey, error) {
	key, err := fsc.GetPrivateKey(legalEntity)

	if err != nil {
		return nil, err
	}

	return &key.PublicKey, nil
}

// Save the private key for the given legalEntity to disk. Since a legalEntity has a URI as identifier, the URI is base64 encoded and postfixed with '_private.pem'. Keys are stored in pem format and are 2k RSA keys.
func (fsc *fileSystemBackend) SavePrivateKey(legalEntity types.LegalEntity, key *rsa.PrivateKey) error {
	filenamePath := fsc.getEntryPath(legalEntity, privateKeyFilePostfix)
	outFile, err := os.Create(filenamePath)

	if err != nil {
		return err
	}

	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)

	return err
}

func (fsc fileSystemBackend) readEntry(entity types.LegalEntity, postfix string) ([]byte, error) {
	filePath := fsc.getEntryPath(entity, postfix)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &FileOpenError{legalEntity: entity.URI, filePath: filePath, err: ErrNotFound}
		}
		return nil, &FileOpenError{legalEntity: entity.URI, filePath: filePath, err: err}
	}
	return data, nil
}

func (fsc fileSystemBackend) getEntryPath(entity types.LegalEntity, postfix string) string {
	return fmt.Sprintf("%s/%s", fsc.fspath, legalEntityToFileName(entity, postfix))
}

func (fsc *fileSystemBackend) createDirs() error {
	f, err := os.Open(fsc.fspath)

	if f != nil {
		f.Close()
	}

	if err != nil {
		err = os.MkdirAll(fsc.fspath, os.ModePerm)
	}

	return err
}

// helper for transforming a legalEntity to something that can be stored on disk
func legalEntityToFileName(legalEntity types.LegalEntity, filePostfix string) string {
	buffer := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	encoder.Write([]byte(legalEntity.URI))
	encoder.Close()

	return fmt.Sprintf("%s_%s", buffer.String(), filePostfix)
}
