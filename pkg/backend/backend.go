// The backend package contains the various options for storing the actual private keys.
// Currently only a file backend is supported
package backend

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/spf13/viper"
)

// Backend interface containing functions for storing and retrieving keys
type Backend interface {
	GetPrivateKey(legalEntity types.LegalEntity) (*rsa.PrivateKey, error)
	GetPublicKey(legalEntity types.LegalEntity) (*rsa.PublicKey, error)
	SavePrivateKey(legalEntity types.LegalEntity, key *rsa.PrivateKey) error
}

// Helper function to create a new CryptoBackend. It checks the config (via Viper) for a --cryptobackend setting
// if none are given or this is set to 'fs', the filesystem backend is used.
func NewCryptoBackend() (Backend, error) {
	if viper.GetString(types.ConfigBackend) == types.ConfigBackendFs || viper.GetString(types.ConfigBackend) == "" {
		fspath := viper.GetString(types.ConfigFSPath)
		if fspath == "" {
			fspath = types.ConfigFSPathDefault
		}

		return NewFileSystemBackend(fspath)
	}

	return nil, types.Error{Msg: "Only fs backend available for now"}
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
