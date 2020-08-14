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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	errors2 "github.com/pkg/errors"
)

type entryType string

const (
	certificateEntry entryType = "certificate.pem"
	privateKeyEntry  entryType = "private.pem"
)

type FileOpenError struct {
	filePath string
	key      types.KeyIdentifier
	err      error
}

// ErrNotFound indicates that the specified crypto storage entry couldn't be found.
var ErrNotFound = errors.New("entry not found")

// ErrInvalidDuration is given when a period duration is 0 or negative
var ErrInvalidDuration = errors.New("given time period is invalid")

// Error returns the string representation
func (f *FileOpenError) Error() string {
	return fmt.Sprintf("could not open entry %s with filename %s: %v", f.key, f.filePath, f.err)
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
	if fspath == "" {
		return nil, errors.New("filesystem path is empty")
	}
	fsc := &fileSystemBackend{
		fspath,
	}

	err := fsc.createDirs()

	if err != nil {
		return nil, err
	}

	return fsc, nil
}

func (fsc *fileSystemBackend) CertificateExists(key types.KeyIdentifier) bool {
	_, err := os.Stat(fsc.getEntryPath(key, certificateEntry))
	return err == nil
}

func (fsc *fileSystemBackend) PrivateKeyExists(key types.KeyIdentifier) bool {
	_, err := os.Stat(fsc.getEntryPath(key, privateKeyEntry))
	return err == nil
}

func (fsc *fileSystemBackend) SaveCertificate(key types.KeyIdentifier, certificate []byte) error {
	filenamePath := fsc.getEntryPath(key, certificateEntry)
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

func (fsc *fileSystemBackend) GetCertificate(key types.KeyIdentifier) (*x509.Certificate, error) {
	rawData, err := fsc.readEntry(key, certificateEntry)
	if err != nil {
		return nil, err
	}
	return cert.PemToX509(rawData)
}

func (fsc *fileSystemBackend) readCertificate(filePath string) (*x509.Certificate, error) {
	rawData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return cert.PemToX509(rawData)
}

// Load the privatekey for the given legalEntity from disk. Since a legalEntity has a URI as identifier, the URI is base64 encoded and postfixed with '_private.pem'. Keys are stored in pem format and are 2k RSA keys.
func (fsc *fileSystemBackend) GetPrivateKey(key types.KeyIdentifier) (*rsa.PrivateKey, error) {
	data, err := fsc.readEntry(key, privateKeyEntry)
	if err != nil {
		return nil, err
	}
	privateKey, err := bytesToPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Load the public key from disk, it load the private key and extract the public key from it.
func (fsc *fileSystemBackend) GetPublicKey(key types.KeyIdentifier) (*rsa.PublicKey, error) {
	privateKey, err := fsc.GetPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

// Save the private key for the given legalEntity to disk. Since a legalEntity has a URI as identifier, the URI is base64 encoded and postfixed with '_private.pem'. Keys are stored in pem format and are 2k RSA keys.
func (fsc *fileSystemBackend) SavePrivateKey(keyIdentifier types.KeyIdentifier, key *rsa.PrivateKey) error {
	filenamePath := fsc.getEntryPath(keyIdentifier, privateKeyEntry)
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

// GetExpiringCertificates naive implementation, uses the fileTree to check every certificate
// it'll not group certificates based on legalEntity. This is up to a more robust implementation
func (fsc *fileSystemBackend) GetExpiringCertificates(from time.Time, till time.Time) ([]*x509.Certificate, error) {
	if from.Equal(till) || from.After(till) {
		return nil, ErrInvalidDuration
	}

	var expiringCertificates = make([]*x509.Certificate, 0)

	// list all files ending on certificateEntry in fcs.path
	err := filepath.Walk(fsc.fspath, func(path string, info os.FileInfo, err error) error {
		// only target expiringCertificates
		if strings.Contains(info.Name(), string(certificateEntry)) {
			certificate, err := fsc.readCertificate(path)
			if err != nil {
				return errors2.Wrap(err, fmt.Sprintf("error parsing file at %s", path))
			}

			// check if not_after is between from and till
			if certificate.NotAfter.After(from) && certificate.NotAfter.Before(till) {
				expiringCertificates = append(expiringCertificates, certificate)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return expiringCertificates, nil
}

func (fsc fileSystemBackend) readEntry(key types.KeyIdentifier, entryType entryType) ([]byte, error) {
	filePath := fsc.getEntryPath(key, entryType)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &FileOpenError{key: key, filePath: filePath, err: ErrNotFound}
		}
		return nil, &FileOpenError{key: key, filePath: filePath, err: err}
	}
	return data, nil
}

func (fsc fileSystemBackend) getEntryPath(key types.KeyIdentifier, entryType entryType) string {
	return filepath.Join(fsc.fspath, getEntryFileName(key, entryType))
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

func getEntryFileName(key types.KeyIdentifier, entryType entryType) string {
	buffer := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	encoder.Write([]byte(key.Owner()))
	encoder.Close()
	var qualifier = ""
	if key.Qualifier() != "" {
		qualifier = "_" + key.Qualifier()
	}
	return fmt.Sprintf("%s%s_%s", buffer.String(), qualifier, entryType)
}
