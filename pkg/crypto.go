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

package pkg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path"
	"sync"

	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/sirupsen/logrus"
)

// MinKeySize defines the minimum (RSA) key size
const MinKeySize = 2048

// ErrInvalidKeySize is returned when the keySize for new keys is too short
var ErrInvalidKeySize = core.NewError(fmt.Sprintf("invalid keySize, needs to be at least %d bits", MinKeySize), false)

// ErrInvalidKeyIdentifier is returned when the provided key identifier isn't valid
var ErrInvalidKeyIdentifier = core.NewError("invalid key identifier", false)

// ErrInvalidAlgorithm indicates an invalid public key was used
var ErrInvalidAlgorithm = core.NewError("invalid algorithm for public key", false)

// ErrKeyAlreadyExists indicates that the key already exists.
var ErrKeyAlreadyExists = errors.New("key already exists")

const TLSCertificateQualifier = "tls"
const SigningCertificateQualifier = "sign"

type CryptoConfig struct {
	Mode          string
	Address       string
	ClientTimeout int
	Keysize       int
	Storage       string
	Fspath        string
}

func (cc CryptoConfig) getFSPath() string {
	if cc.Fspath == "" {
		return DefaultCryptoConfig().Fspath
	} else {
		return cc.Fspath
	}
}

func DefaultCryptoConfig() CryptoConfig {
	return CryptoConfig{
		Address:       "localhost:1323",
		ClientTimeout: 10,
		Keysize:       2048,
		Storage:       "fs",
		Fspath:        "./",
	}
}

// default implementation for CryptoInstance
type Crypto struct {
	Storage      storage.Storage
	Config       CryptoConfig
	trustStore   cert.TrustStore
	configOnce   sync.Once
	configDone   bool
	certMonitors []*storage.CertificateMonitor
}

type opaquePrivateKey struct {
	publicKey crypto.PublicKey
	signFn    func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

func (k opaquePrivateKey) Public() crypto.PublicKey {
	return k.publicKey
}

func (k opaquePrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.signFn(rand, digest, opts)
}

// Start the certificate monitors
func (client *Crypto) Start() error {
	client.certMonitors = storage.DefaultCertificateMonitors(client.Storage)

	for _, m := range client.certMonitors {
		if err := m.Start(); err != nil {
			return err
		}
	}

	return nil
}

// Shutdown stops the certificate monitors
func (client *Crypto) Shutdown() error {
	for _, m := range client.certMonitors {
		m.Stop()
	}
	return nil
}

// GetPrivateKey returns the specified private key. It can be used for signing, but cannot be exported.
func (client *Crypto) GetPrivateKey(key types.KeyIdentifier) (crypto.Signer, error) {
	priv, err := client.Storage.GetPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return opaquePrivateKey{publicKey: &priv.PublicKey, signFn: priv.Sign}, nil
}

func vendorEntity() types.LegalEntity {
	identity := core.NutsConfig().VendorID()
	return types.LegalEntity{URI: identity.String()}
}

var instance *Crypto

var oneBackend sync.Once

func CryptoInstance() *Crypto {
	if instance != nil {
		return instance
	}
	oneBackend.Do(func() {
		instance = NewCryptoInstance(DefaultCryptoConfig())
	})
	return instance
}

func NewCryptoInstance(config CryptoConfig) *Crypto {
	return &Crypto{
		Config: config,
	}
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (client *Crypto) Configure() error {
	var err error
	client.configOnce.Do(func() {
		if core.NutsConfig().GetEngineMode(client.Config.Mode) != core.ServerEngineMode {
			return
		}
		if err = client.doConfigure(); err == nil {
			client.configDone = true
		}
	})
	return err
}

func (client *Crypto) doConfigure() error {
	if err := client.verifyKeySize(client.Config.Keysize); err != nil {
		return err
	}
	if client.Config.Storage != "fs" && client.Config.Storage != "" {
		return errors.New("only fs backend available for now")
	}
	var err error
	if client.Storage, err = storage.NewFileSystemBackend(client.Config.getFSPath()); err != nil {
		return err
	}
	if client.trustStore, err = cert.NewTrustStore(path.Join(client.Config.getFSPath(), "truststore.pem")); err != nil {
		return err
	}
	return nil
}

// GenerateKeyPair generates a new key pair. If a key pair with the same identifier already exists, it is overwritten.
func (client *Crypto) GenerateKeyPair(key types.KeyIdentifier, overwrite bool) (crypto.PublicKey, error) {
	privateKey, err := client.generateAndStoreKeyPair(key, overwrite)
	if err != nil {
		return nil, err
	}
	return privateKey.Public(), nil
}

func (client *Crypto) generateAndStoreKeyPair(key types.KeyIdentifier, overwrite bool) (*rsa.PrivateKey, error) {
	if key == nil || key.Owner() == "" {
		return nil, ErrInvalidKeyIdentifier
	}
	if !overwrite && client.PrivateKeyExists(key) {
		logrus.Warnf("Unable to generate new key pair for %s: it already exists and overwrite=false", key)
		return nil, ErrKeyAlreadyExists
	}
	if keyPair, err := client.generateKeyPair(); err != nil {
		return nil, err
	} else {
		if err = client.Storage.SavePrivateKey(key, keyPair); err != nil {
			return nil, err
		} else {
			return keyPair, nil
		}
	}
}

func (client *Crypto) generateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, client.Config.Keysize)
}

// SignFor signs a piece of data using the given key. It is expected that the plain data is given, and it uses the SHA256 hashing function.
// todo: SHA_256?
func (client *Crypto) Sign(data []byte, key types.KeyIdentifier) ([]byte, error) {
	// random
	rng := rand.Reader

	rsaPrivateKey, err := client.Storage.GetPrivateKey(key)
	hashedData := sha256.Sum256(data)

	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rng, rsaPrivateKey, crypto.SHA256, hashedData[:])

	if err != nil {
		return nil, err
	}

	return signature, err
}

// PrivateKeyExists checks storage for an entry for the given legal entity and returns true if it exists
func (client *Crypto) PrivateKeyExists(key types.KeyIdentifier) bool {
	return client.Storage.PrivateKeyExists(key)
}

// PublicKeyInPEM loads the key from storage and returns it as PEM encoded. Only supports RSA style keys
func (client *Crypto) GetPublicKeyAsPEM(key types.KeyIdentifier) (string, error) {
	pubKey, err := client.Storage.GetPublicKey(key)

	if err != nil {
		return "", err
	}

	return cert.PublicKeyToPem(pubKey)
}

func (client Crypto) TrustStore() cert.TrustStore {
	return client.trustStore
}

func (client *Crypto) verifyKeySize(keySize int) error {
	if keySize < MinKeySize && core.NutsConfig().InStrictMode() {
		return ErrInvalidKeySize
	}
	return nil
}
