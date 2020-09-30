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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	errors2 "github.com/pkg/errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/log"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
)

// MinKeySize defines the minimum (RSA) key size
const MinKeySize = 2048

// ErrInvalidKeySize is returned when the keySize for new keys is too short
var ErrInvalidKeySize = core.NewError(fmt.Sprintf("invalid keySize, needs to be at least %d bits", MinKeySize), false)

// ErrInvalidKeyIdentifier is returned when the provided key identifier isn't valid
var ErrInvalidKeyIdentifier = core.NewError("invalid key identifier", false)

// ErrMissingActor indicates the actor is missing
var ErrMissingActor = core.NewError("missing actor", false)

// ErrMissingSubject indicates the Subject is missing
var ErrMissingSubject = core.NewError("missing subject", false)

// ErrIllegalNonce indicates an incorrect nonce
var ErrIllegalNonce = core.NewError("illegal nonce given", false)

// ErrInvalidAlgorithm indicates an invalid public key was used
var ErrInvalidAlgorithm = core.NewError("invalid algorithm for public key", false)

// ErrUnableToParseCSR indicates the CSR is invalid
var ErrUnableToParseCSR = core.NewError("unable to parse CSR", false)

// ErrCSRSignatureInvalid indicates the signature on the CSR (Proof of Possesion) is invalid
var ErrCSRSignatureInvalid = core.NewError("CSR signature is invalid", false)

// ErrUnknownCA indicates that the signing CA is unknown (e.g. its keys are unavailable for signing)
var ErrUnknownCA = core.NewError("unknown CA", false)

// ErrInvalidCertChain indicates that the provided X.509 certificate chain is invalid
// noinspection GoErrorStringFormat
var ErrInvalidCertChain = errors.New("X.509 certificate chain is invalid")

// ErrCertificateNotTrusted indicates that the X.509 certificate is not trusted
// noinspection GoErrorStringFormat
var ErrCertificateNotTrusted = errors.New("X.509 certificate not trusted")

// ErrKeyAlreadyExists indicates that the key already exists.
var ErrKeyAlreadyExists = errors.New("key already exists")

// jwsAlgorithm holds the supported (required) JWS signing algorithm
const jwsAlgorithm = jwa.RS256

// TLSCertificateValidityInDays holds the number of days issued TLS certificates are valid
const TLSCertificateValidityInDays = 365

// SigningCertificateValidityInDays holds the number of days issued signing certificates are valid
const SigningCertificateValidityInDays = 365

// vendorCACertificateDaysValid holds the number of days self-signed Vendor CA certificates are valid
const vendorCACertificateDaysValid = 1095

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

// SignCertificate issues a certificate by signing a PKCS10 certificate request. The private key of the specified CA should be available in the key store.
func (client *Crypto) SignCertificate(subjectKey types.KeyIdentifier, caKey types.KeyIdentifier, pkcs10 []byte, profile CertificateProfile) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(pkcs10)
	if err != nil {
		return nil, errors2.Wrap(err, ErrUnableToParseCSR.Error())
	}
	log.Logger().Infof("Issuing certificate based on CSR, ca=%s, entity=%s, subject=%s, self-signed=%t", caKey, subjectKey, csr.Subject.String(), subjectKey == caKey)
	err = csr.CheckSignature()
	if err != nil {
		return nil, errors2.Wrap(err, ErrCSRSignatureInvalid.Error())
	}
	certificate, err := client.signCertificate(csr, caKey, profile, subjectKey == caKey)
	if err != nil {
		return nil, err
	}
	err = client.Storage.SaveCertificate(subjectKey, certificate)
	if err != nil {
		return nil, errors2.Wrap(err, "unable to save certificate to store")
	}

	return certificate, nil
}

func (client *Crypto) StoreVendorCACertificate(certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("certificate is nil")
	}
	identity := core.NutsConfig().Identity()
	log.Logger().Infof("Storing CA certificate for: %s", identity)
	key := types.KeyForEntity(types.LegalEntity{URI: identity})
	if !client.Storage.PrivateKeyExists(key) {
		return fmt.Errorf("private key not present for key: %s", key)
	}
	if publicKey, err := client.Storage.GetPublicKey(key); err != nil {
		return err
	} else if !reflect.DeepEqual(publicKey, certificate.PublicKey) {
		return fmt.Errorf("public key in certificate does not match stored private key (key: %s)", key)
	}
	return client.Storage.SaveCertificate(key, certificate.Raw)
}

func (client *Crypto) SelfSignVendorCACertificate(name string) (*x509.Certificate, error) {
	identity := core.NutsConfig().Identity()
	var csr *x509.CertificateRequest
	csrAsASN1, privateKey, err := client.generateVendorCACSR(name, identity)
	if err != nil {
		return nil, err
	} else {
		if csr, err = x509.ParseCertificateRequest(csrAsASN1); err != nil {
			return nil, errors2.Wrap(err, "unable to parse CSR")
		}
	}
	serialNumber, err := cert.SerialNumber()
	if err != nil {
		return nil, errors2.Wrap(err, "unable to generate certificate serial number")
	}
	template := &x509.Certificate{
		PublicKey:             csr.PublicKey,
		SerialNumber:          serialNumber,
		Issuer:                csr.Subject,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, vendorCACertificateDaysValid),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtraExtensions:       csr.Extensions,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	log.Logger().Infof("Self-signing Vendor CA certificate for vendor: %s", name)
	if certificate, err := x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, privateKey); err != nil {
		return nil, errors2.Wrap(err, "unable to create certificate")
	} else {
		return x509.ParseCertificate(certificate)
	}
}

func (client *Crypto) GenerateVendorCACSR(name string) ([]byte, error) {
	identity := core.NutsConfig().Identity()
	log.Logger().Infof("Generating CSR for Vendor CA certificate (for current vendor: %s, name: %s)", identity, name)
	if pkcs10, _, err := client.generateVendorCACSR(name, identity); err != nil {
		return nil, err
	} else {
		return pkcs10, nil
	}
}

func (client *Crypto) generateVendorCACSR(name string, identity string) ([]byte, crypto.PrivateKey, error) {
	if strings.TrimSpace(name) == "" {
		return nil, nil, errors.New("invalid name")
	}
	key := types.KeyForEntity(types.LegalEntity{URI: identity})
	if !client.Storage.PrivateKeyExists(key) {
		log.Logger().Infof("No private key for %s generating.", identity)
		_, err := client.GenerateKeyPair(key, false)
		if err != nil {
			return nil, nil, err
		}
	}
	privateKey, err := client.GetPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	csr, err := cert.VendorCertificateRequest(identity, name, "CA", "healthcare") // TODO: Domain is now hardcoded
	if err != nil {
		return nil, nil, errors2.Wrap(err, "unable to create CSR template")
	}
	csr.PublicKey = privateKey.Public()
	pkcs10, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
	if err != nil {
		return nil, nil, errors2.Wrap(err, "unable to create CSR")
	}
	return pkcs10, privateKey, nil
}

func (client *Crypto) GetSigningCertificate(entity types.LegalEntity) (*x509.Certificate, crypto.PrivateKey, error) {
	key := types.KeyForEntity(entity).WithQualifier(SigningCertificateQualifier)
	return client.getCertificateAndKey(key)
}

func (client *Crypto) RenewSigningCertificate(entity types.LegalEntity) (*x509.Certificate, crypto.PrivateKey, error) {
	return client.issueSubCertificate(entity, SigningCertificateQualifier, CertificateProfile{
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		NumDaysValid: SigningCertificateValidityInDays,
	})
}

func (client *Crypto) GetTLSCertificate(entity types.LegalEntity) (*x509.Certificate, crypto.PrivateKey, error) {
	key := types.KeyForEntity(entity).WithQualifier(TLSCertificateQualifier)
	return client.getCertificateAndKey(key)
}

func (client *Crypto) RenewTLSCertificate(entity types.LegalEntity) (*x509.Certificate, crypto.PrivateKey, error) {
	return client.issueSubCertificate(entity, TLSCertificateQualifier, CertificateProfile{
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		NumDaysValid: TLSCertificateValidityInDays,
	})
}

// issueSubCertificate issues a 'sub certificate' for the specified entity, meaning a certificate issued by ('under') the CA
// certificate of the entity. This is useful for providing specialized certificates for specific use cases (TLS and signing).
// The entity must have a (valid) CA certificate and its private key must be present.
func (client *Crypto) issueSubCertificate(entity types.LegalEntity, qualifier string, profile CertificateProfile) (*x509.Certificate, crypto.PrivateKey, error) {
	log.Logger().Infof("Renewing '%s' certificate for entity: %s", qualifier, entity)
	if qualifier == "" {
		return nil, nil, errors.New("missing qualifier")
	}
	caKey := types.KeyForEntity(entity)
	caCertificate, err := client.Storage.GetCertificate(caKey)
	if err != nil || caCertificate == nil {
		return nil, nil, fmt.Errorf("unable to retrieve CA certificate %s: %v", caKey, err)
	}
	if len(caCertificate.Subject.Organization) == 0 {
		return nil, nil, fmt.Errorf("subject of CA certificate %s doesn't contain 'O' component", caKey)
	}
	if len(caCertificate.Subject.Country) == 0 {
		return nil, nil, fmt.Errorf("subject of CA certificate %s doesn't contain 'C' component", caKey)
	}
	certKey := caKey.WithQualifier(qualifier)
	var certificate *x509.Certificate
	var privateKey *rsa.PrivateKey
	if privateKey, err = client.generateAndStoreKeyPair(certKey, true); err != nil {
		return nil, nil, errors2.Wrapf(err, "unable to generate key pair for new %s certificate (%s)", certKey.Qualifier(), certKey)
	}
	csr := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      caCertificate.Subject.Country,
			Organization: caCertificate.Subject.Organization,
			CommonName:   caCertificate.Subject.Organization[0],
		},
		PublicKey: privateKey.Public(),
		// Copy Subject Alternative Name (SAN) extensions. Since Node CA only issues certificates to itself, any SAN
		// applicable to the CA are also applicable to the certificates it issues.
		Extensions: cert.CopySANs(caCertificate),
	}
	certificateAsBytes, err := client.signCertificate(&csr, caKey, profile, false)
	if err != nil {
		return nil, nil, errors2.Wrapf(err, "unable to issue %s certificate %s", certKey.Qualifier(), caKey)
	}
	certificate, err = x509.ParseCertificate(certificateAsBytes)
	if err != nil {
		return nil, nil, err
	}
	if err = client.Storage.SaveCertificate(certKey, certificateAsBytes); err != nil {
		return nil, nil, errors2.Wrapf(err, "unable to store issued %s certificate", certKey.Qualifier())
	}
	return certificate, privateKey, nil
}

func (client *Crypto) getCertificateAndKey(certKey types.KeyIdentifier) (*x509.Certificate, crypto.PrivateKey, error) {
	var err error
	var certificate *x509.Certificate
	var key crypto.PrivateKey
	if client.Storage.CertificateExists(certKey) {
		if certificate, err = client.Storage.GetCertificate(certKey); err != nil {
			return nil, nil, err
		} else if err := cert.ValidateCertificate(certificate, cert.ValidAt(time.Now())); err != nil {
			log.Logger().Infof("Current '%s' certificate (%s) isn't currently valid, should issue new one (not before=%s,not after=%s)", certKey.Qualifier(), certKey, certificate.NotBefore, certificate.NotAfter)
			return nil, nil, nil
		}
		if key, err = client.Storage.GetPrivateKey(certKey); err != nil {
			return nil, nil, errors2.Wrapf(err, "unable to retrieve private key for certificate: %s", certKey)
		}
		return certificate, key, nil
	}
	log.Logger().Infof("No '%s' certificate (%s) found, should issue new one.", certKey.Qualifier(), certKey)
	return nil, nil, nil
}

func (client *Crypto) signCertificate(csr *x509.CertificateRequest, caKey types.KeyIdentifier, profile CertificateProfile, selfSigned bool) ([]byte, error) {
	key, err := client.Storage.GetPrivateKey(caKey)
	if err != nil || key == nil {
		return nil, errors2.Wrap(err, ErrUnknownCA.Error())
	}

	serialNumber, err := cert.SerialNumber()
	if err != nil {
		return nil, errors2.Wrap(err, "unable to generate serial number")
	}
	template := &x509.Certificate{
		SerialNumber:    serialNumber,
		Subject:         csr.Subject,
		NotBefore:       time.Now(),
		KeyUsage:        profile.KeyUsage,
		ExtKeyUsage:     profile.ExtKeyUsage,
		NotAfter:        time.Now().AddDate(0, 0, profile.NumDaysValid),
		ExtraExtensions: csr.Extensions,
		PublicKey:       csr.PublicKey,
	}
	if !profile.notBefore.IsZero() && !profile.notAfter.IsZero() {
		template.NotBefore = profile.notBefore
		template.NotAfter = profile.notAfter
	}
	if profile.IsCA {
		template.IsCA = true
		template.MaxPathLen = profile.MaxPathLen
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCRLSign
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	var parentTemplate *x509.Certificate
	if selfSigned {
		parentTemplate = template
	} else {
		var parentCertificate *x509.Certificate
		if parentCertificate, err = client.Storage.GetCertificate(caKey); err != nil {
			return nil, errors2.Wrap(err, ErrUnknownCA.Error())
		}
		if err := cert.ValidateCertificate(parentCertificate, cert.IsCA(), cert.ValidBetween(template.NotBefore, template.NotAfter)); err != nil {
			return nil, errors2.Wrap(err, "CA certificate validation failed")
		}
		parentTemplate = parentCertificate
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, parentTemplate, csr.PublicKey, key)
	if err != nil {
		return nil, errors2.Wrap(err, "unable to create certificate")
	}
	log.Logger().Infof("Issued certificate, subject=%s, serialNumber=%d", template.Subject.String(), template.SerialNumber)
	return certificate, nil
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

// Main decryption function, first the symmetric key will be decrypted using the private key of the legal entity.
// The resulting symmetric key will then be used to decrypt the given cipherText.
func (client *Crypto) DecryptKeyAndCipherText(cipherText types.DoubleEncryptedCipherText, key types.KeyIdentifier) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidKeyIdentifier
	}
	if len(cipherText.CipherTextKeys) != 1 {
		return nil, core.Errorf("unsupported count of CipherTextKeys: %d", false, len(cipherText.CipherTextKeys))
	}

	symmKey, err := client.decryptCipherTextFor(cipherText.CipherTextKeys[0], key)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(symmKey)

	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	plaintext, err := decryptWithSymmetricKey(cipherText.CipherText, aesgcm, cipherText.Nonce)

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptKeyAndPlainTextFor encrypts a piece of data for the given public key
func (client *Crypto) EncryptKeyAndPlainText(plainText []byte, keys []jwk.Key) (types.DoubleEncryptedCipherText, error) {
	cipherBytes, cipher, err := generateSymmetricKey()

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	cipherText, nonce, err := encryptWithSymmetricKey(plainText, cipher)

	if err != nil {
		return types.DoubleEncryptedCipherText{}, err
	}

	var cipherTextKeys [][]byte

	for _, jwk := range keys {
		pk, err := jwk.Materialize()
		if err != nil {
			return types.DoubleEncryptedCipherText{}, err
		}

		// todo support EC
		if rsaPk, ok := pk.(*rsa.PublicKey); ok {
			encSymKey, err := client.encryptPlainTextWith(cipherBytes, rsaPk)
			if err != nil {
				return types.DoubleEncryptedCipherText{}, err
			}
			cipherTextKeys = append(cipherTextKeys, encSymKey)
		} else {
			return types.DoubleEncryptedCipherText{}, ErrInvalidAlgorithm
		}
	}

	return types.DoubleEncryptedCipherText{
		Nonce:          nonce,
		CipherText:     cipherText,
		CipherTextKeys: cipherTextKeys,
	}, nil
}

func (client *Crypto) generateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, client.Config.Keysize)
}

func encryptWithSymmetricKey(plainText []byte, key cipher.AEAD) (cipherText []byte, nonce []byte, error error) {
	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	cipherText = key.Seal(nil, nonce, plainText, nil)

	return cipherText, nonce, nil
}

func generateSymmetricKey() ([]byte, cipher.AEAD, error) {
	symkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, symkey); err != nil {
		return nil, nil, err
	}

	aead, err := symmetricKeyToBlockCipher(symkey)

	return symkey, aead, err
}

func symmetricKeyToBlockCipher(ciph []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(ciph)

	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// CalculateExternalId creates an unique identifier which is repeatable. It uses the legalEntity private key as key.
// This is not for security but does generate the same unique identifier every time. It should only be used as unique identifier for consent records. Using the private key also ensure the BSN can not be deduced from the externalID.
// todo: check by others if this makes sense
func (client *Crypto) CalculateExternalId(subject string, actor string, key types.KeyIdentifier) ([]byte, error) {
	if len(strings.TrimSpace(subject)) == 0 {
		return nil, ErrMissingSubject
	}

	if len(strings.TrimSpace(actor)) == 0 {
		return nil, ErrMissingActor
	}

	pk, err := client.Storage.GetPrivateKey(key)
	if err != nil {
		return nil, err
	}

	// Create a new HMAC
	h := hmac.New(sha256.New, pk.D.Bytes())
	h.Write([]byte(subject))
	h.Write([]byte(actor))

	return h.Sum(nil), nil
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

// VerifyWith verfifies a signature of some data with a given PublicKeyInPEM. It uses the SHA256 hashing function.
func (client *Crypto) VerifyWith(data []byte, sig []byte, key jwk.Key) (bool, error) {
	hashedData := sha256.Sum256(data)

	mKey, err := key.Materialize()
	if err != nil {
		return false, err
	}

	if k, ok := mKey.(*rsa.PublicKey); ok {
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, hashedData[:], sig); err != nil {
			return false, err
		}
		return true, nil
	}

	// todo support EC sigs
	//if k, ok := mKey.(*ecdsa.PublicKey); ok {
	//	if err := ecdsa.Verify(k, crypto.SHA256, hashedData[:], sig); err != nil {
	//		return false, err
	//	}
	//	return true, nil
	//}

	return false, ErrInvalidAlgorithm
}

// PublicKeyInPEM loads the key from storage and returns it as PEM encoded. Only supports RSA style keys
func (client *Crypto) GetPublicKeyAsPEM(key types.KeyIdentifier) (string, error) {
	pubKey, err := client.Storage.GetPublicKey(key)

	if err != nil {
		return "", err
	}

	return cert.PublicKeyToPem(pubKey)
}

// PublicKeyInJWK loads the key from storage and wraps it in a Key format. Supports RSA, ECDSA and Symmetric style keys
func (client *Crypto) GetPublicKeyAsJWK(key types.KeyIdentifier) (jwk.Key, error) {
	pubKey, err := client.Storage.GetPublicKey(key)

	if err != nil {
		return nil, err
	}

	return jwk.New(pubKey)
}

// SignJwtFor creates a signed JWT given a legalEntity and map of claims
func (client *Crypto) SignJWT(claims map[string]interface{}, key types.KeyIdentifier) (string, error) {
	rsaPrivateKey, err := client.Storage.GetPrivateKey(key)

	if err != nil {
		return "", err
	}

	c := jwt.MapClaims{}
	for k, v := range claims {
		c[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	return token.SignedString(rsaPrivateKey)
}

func (client Crypto) SignJWS(payload []byte, key types.KeyIdentifier) ([]byte, error) {
	certificate, privateKey, err := client.getCertificateAndKey(key)
	if err != nil {
		return nil, errors2.Wrapf(err, "error while retrieving signing certificate and key (%s)", key)
	}
	if certificate == nil || privateKey == nil {
		return nil, fmt.Errorf("signing certificate and/or private not present: %s", key)
	}
	if err := cert.ValidateCertificate(certificate, cert.MeantForSigning()); err != nil {
		return nil, err
	}
	headers := jws.StandardHeaders{
		JWSx509CertChain: cert.MarshalX509CertChain([]*x509.Certificate{certificate}),
	}
	return jws.Sign(payload, jwsAlgorithm, privateKey, jws.WithHeaders(&headers))
}

func (client Crypto) SignJWSEphemeral(payload []byte, caKey types.KeyIdentifier, csr x509.CertificateRequest, signingTime time.Time) ([]byte, error) {
	// Generate ephemeral key and certificate
	entityPrivateKey, err := client.generateKeyPair()
	if err != nil {
		return nil, err
	}
	csr.PublicKey = &entityPrivateKey.PublicKey
	asn1Cert, err := client.signCertificate(&csr, caKey, CertificateProfile{
		KeyUsage:  x509.KeyUsageDigitalSignature,
		notBefore: signingTime,
		notAfter:  signingTime.Add(time.Minute),
	}, false)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(asn1Cert)
	if err != nil {
		return nil, err
	}
	// Now sign
	headers := jws.StandardHeaders{
		JWSx509CertChain: cert.MarshalX509CertChain([]*x509.Certificate{certificate}),
	}
	return jws.Sign(payload, jwsAlgorithm, entityPrivateKey, jws.WithHeaders(&headers))
}

func (client *Crypto) VerifyJWS(signature []byte, signingTime time.Time, certVerifier cert.Verifier) ([]byte, error) {
	m, err := jws.Parse(bytes.NewReader(signature))
	if err != nil {
		return nil, errors2.Wrap(err, "unable to parse signature")
	}
	if len(m.Signatures()) == 0 {
		return nil, errors.New("JWS contains no signatures")
	}
	if len(m.Signatures()) > 1 {
		return nil, errors.New("JWS contains more than 1 signature")
	}

	sig := m.Signatures()[0]
	if sig.ProtectedHeaders().Algorithm() != jwsAlgorithm {
		return nil, fmt.Errorf("JWS is signed with incorrect algorithm (expected = %v, actual = %v)", jwsAlgorithm, sig.ProtectedHeaders().Algorithm())
	}

	// Parse X509 certificate chain
	certChain, err := cert.GetX509ChainFromHeaders(sig.ProtectedHeaders())
	if err != nil {
		return nil, errors2.Wrap(err, ErrInvalidCertChain.Error())
	}
	if len(certChain) == 0 {
		return nil, fmt.Errorf("JWK doesn't contain X509 chain header (%s) header", jws.X509CertChainKey)
	}
	signingCert := certChain[0]
	// Check key strength. Cast should be safe since we checked the algorithm.
	if signingPubKey, ok := signingCert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("invalid key type, expected *rsa.PublicKey")
	} else if err := client.verifyKeySize(signingPubKey.Size() * 8); err != nil {
		return nil, err
	}
	// Check certificate is trusted
	if err := certVerifier.Verify(signingCert, signingTime); err != nil {
		return nil, errors2.Wrap(err, ErrCertificateNotTrusted.Error())
	}
	// Check if the KeyUsage of the certificate is applicable for signing
	if err := cert.ValidateCertificate(signingCert, cert.MeantForSigning()); err != nil {
		return nil, err
	}
	// TODO: CRL checking
	return jws.Verify(signature, sig.ProtectedHeaders().Algorithm(), signingCert.PublicKey)
}

func (client Crypto) TrustStore() cert.TrustStore {
	return client.trustStore
}

// Decrypt a piece of data for the given legalEntity. It loads the private key from the storage and decrypts the cipherText.
// It returns an error if the given legalEntity does not have a private key.
func (client *Crypto) decryptCipherTextFor(cipherText []byte, key types.KeyIdentifier) ([]byte, error) {

	privateKey, err := client.Storage.GetPrivateKey(key)

	if err != nil {
		return nil, err
	}

	plainText, err := decryptWithPrivateKey(cipherText, privateKey)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Encrypt a piece of data for a legalEntity. Usually encryptPlainTextWith will be used with a public key of a different (unknown) legalEntity.
// It returns an error if the given legalEntity does not have a private key.
func (client *Crypto) encryptPlainTextFor(plaintext []byte, key types.KeyIdentifier) ([]byte, error) {

	publicKey, err := client.Storage.GetPublicKey(key)

	if err != nil {
		return nil, err
	}

	return client.encryptPlainTextWith(plaintext, publicKey)
}

// Encrypt a piece of data with the given public key
func (client *Crypto) encryptPlainTextWith(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {

	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, key, plaintext, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func decryptWithPrivateKey(cipherText []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func decryptWithSymmetricKey(cipherText []byte, key cipher.AEAD, nonce []byte) ([]byte, error) {
	if len(nonce) == 0 {
		return nil, ErrIllegalNonce
	}

	plaintext, err := key.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (client *Crypto) verifyKeySize(keySize int) error {
	if keySize < MinKeySize && core.NutsConfig().InStrictMode() {
		return ErrInvalidKeySize
	}
	return nil
}
