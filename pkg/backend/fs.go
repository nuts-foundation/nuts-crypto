package backend

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	"io/ioutil"
	"os"
)

const privateKeyFilePostfix = "private.pem"

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
// Load the privatekey for the given legalEntity from disk. Since a legalEntity has a URI as identifier, the URI is base64 encoded and postfixed with '_private.pem'. Keys are stored in pem format and are 2k RSA keys.
func (fsc *fileSystemBackend) GetPrivateKey(legalEntity types.LegalEntity) (*rsa.PrivateKey, error) {

	fileName := legalEntityToFileName(legalEntity, privateKeyFilePostfix)
	filePath := fmt.Sprintf("%s/%s", fsc.fspath, fileName)

	bytes, err := ioutil.ReadFile(filePath)

	if err != nil {
		return nil, err
	}

	var key *rsa.PrivateKey
	key, err = bytesToPrivateKey(bytes)

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
	filenamePath := fmt.Sprintf("%s/%s", fsc.fspath, legalEntityToFileName(legalEntity, privateKeyFilePostfix))
	outFile, err := os.Create(filenamePath)

	if err != nil {
		return err
	}

	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)

	return err
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
	encoder.Write([]byte(legalEntity.Uri))
	encoder.Close()

	return fmt.Sprintf("%s_%s", buffer.String(), filePostfix)
}
