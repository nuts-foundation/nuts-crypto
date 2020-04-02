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
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	errors2 "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
)

// MinKeySize defines the minimum (RSA) key size
const MinKeySize = 2048

// ErrInvalidKeySize is returned when the keySize for new keys is too short
var ErrInvalidKeySize = core.NewError(fmt.Sprintf("invalid keySize, needs to be at least %d bits", MinKeySize), false)

// ErrMissingLegalEntityURI is returned when a required legal entity is missing
var ErrMissingLegalEntityURI = core.NewError("missing legalEntity URI", false)

// ErrMissingActor indicates the actor is missing
var ErrMissingActor = core.NewError("missing actor", false)

// ErrMissingSubject indicates the Subject is missing
var ErrMissingSubject = core.NewError("missing subject", false)

// ErrIllegalNonce indicates an incorrect nonce
var ErrIllegalNonce = core.NewError("illegal nonce given", false)

// ErrWrongPublicKey indicates a wrong public key format
var ErrWrongPublicKey = core.NewError("failed to decode PEM block containing public key, key is of the wrong type", false)

// ErrRsaPubKeyConversion indicates a public key could not be converted to an RSA public key
var ErrRsaPubKeyConversion = core.NewError("Unable to convert public key to RSA public key", false)

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

// ModuleName == Registry
const ModuleName = "Crypto"

// jwsAlgorithm holds the supported (required) JWS signing algorithm
const jwsAlgorithm = jwa.RS256

type CryptoConfig struct {
	Keysize int
	Storage string
	Fspath  string
}

// default implementation for CryptoInstance
type Crypto struct {
	Storage    storage.Storage
	Config     CryptoConfig
	configOnce sync.Once
	configDone bool
	_logger    *logrus.Entry
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

// GetOpaquePrivateKey returns the current private key for a given legal entity. It can be used for signing, but cannot be exported.
func (client *Crypto) GetOpaquePrivateKey(entity types.LegalEntity) (crypto.Signer, error) {
	priv, err := client.Storage.GetPrivateKey(entity)
	if err != nil {
		return nil, err
	}
	return opaquePrivateKey{publicKey: &priv.PublicKey, signFn: priv.Sign}, nil
}

// SignCertificate issues a certificate by signing a PKCS10 certificate request. The private key of the specified CA should be available in the key store.
func (client *Crypto) SignCertificate(entity types.LegalEntity, ca types.LegalEntity, pkcs10 []byte, profile CertificateProfile) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(pkcs10)
	if err != nil {
		return nil, errors2.Wrap(err, ErrUnableToParseCSR.Error())
	}
	client.logger().Infof("Issuing certificate for CSR, ca=%s, entity=%s, subject=%s, self-signed=%t", ca.URI, entity.URI, csr.Subject.String(), entity == ca)
	err = csr.CheckSignature()
	if err != nil {
		return nil, errors2.Wrap(err, ErrCSRSignatureInvalid.Error())
	}
	certificate, err := client.signCertificate(csr, ca, profile, entity == ca)
	if err != nil {
		return nil, err
	}
	err = client.Storage.SaveCertificate(entity, certificate)
	if err != nil {
		return nil, errors2.Wrap(err, "unable to save certificate to store")
	}

	return certificate, nil
}

func (client *Crypto) signCertificate(csr *x509.CertificateRequest, ca types.LegalEntity, profile CertificateProfile, selfSigned bool) ([]byte, error) {
	key, err := client.Storage.GetPrivateKey(ca)
	if err != nil || key == nil {
		return nil, errors2.Wrap(err, ErrUnknownCA.Error())
	}

	serialNumber, err := serialNumber()
	if err != nil {
		return nil, errors2.Wrap(err, "unable to generate serial number")
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(serialNumber),
		Subject:         csr.Subject,
		NotBefore:       time.Now(),
		KeyUsage:        profile.KeyUsage,
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
		parentCertificate, err := client.Storage.GetCertificate(ca)
		if err != nil {
			return nil, errors2.Wrap(err, ErrUnknownCA.Error())
		}
		parentTemplate = parentCertificate
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, parentTemplate, csr.PublicKey, key)
	if err != nil {
		return nil, errors2.Wrap(err, "unable to create certificate")
	}
	client.logger().Infof("Issued certificate, subject=%s, serialNumber=%d", template.Subject.String(), template.SerialNumber)
	return certificate, nil
}

var instance *Crypto

var oneBackend sync.Once

func CryptoInstance() *Crypto {
	oneBackend.Do(func() {
		instance = &Crypto{
			Config: CryptoConfig{
				Keysize: types.ConfigKeySizeDefault,
			},
		}
	})
	return instance
}

// Configure loads the given configurations in the engine. Any wrong combination will return an error
func (client *Crypto) Configure() error {
	var err error

	client.configOnce.Do(func() {
		if client.Config.Keysize < MinKeySize {
			err = ErrInvalidKeySize
			return
		}

		client.Storage, err = client.newCryptoStorage()
		client.configDone = true
	})

	return err
}

// Helper function to create a new CryptoInstance. It checks the config (via Viper) for a --cryptobackend setting
// if none are given or this is set to 'fs', the filesystem backend is used.
func (client *Crypto) newCryptoStorage() (storage.Storage, error) {
	if client.Config.Storage == types.ConfigStorageFs || client.Config.Storage == "" {
		fspath := client.Config.Fspath
		if fspath == "" {
			fspath = types.ConfigFSPathDefault
		}

		return storage.NewFileSystemBackend(fspath)
	}

	return nil, errors.New("only fs backend available for now")
}

// generate a new rsa keypair for the given legalEntity. The legalEntity uri is base64 encoded and used as filename
// for the key.
func (client *Crypto) GenerateKeyPairFor(legalEntity types.LegalEntity) error {
	var err error = nil

	if len(legalEntity.URI) == 0 {
		return ErrMissingLegalEntityURI
	}

	key, err := client.generateKeyPair()

	if err != nil {
		return err
	}

	err = client.Storage.SavePrivateKey(legalEntity, key)

	return err
}

// Main decryption function, first the symmetric key will be decrypted using the private key of the legal entity.
// The resulting symmetric key will then be used to decrypt the given cipherText.
func (client *Crypto) DecryptKeyAndCipherTextFor(cipherText types.DoubleEncryptedCipherText, legalEntity types.LegalEntity) ([]byte, error) {

	if len(cipherText.CipherTextKeys) != 1 {
		return nil, core.Errorf("unsupported count of CipherTextKeys: %d", false, len(cipherText.CipherTextKeys))
	}

	symmKey, err := client.decryptCipherTextFor(cipherText.CipherTextKeys[0], legalEntity)

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
func (client *Crypto) EncryptKeyAndPlainTextWith(plainText []byte, keys []jwk.Key) (types.DoubleEncryptedCipherText, error) {
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

// ExternalIdFor creates an unique identifier which is repeatable. It uses the legalEntity private key as key.
// This is not for security but does generate the same unique identifier every time. It should only be used as unique identifier for consent records. Using the private key also ensure the BSN can not be deduced from the externalID.
// todo: check by others if this makes sense
func (client *Crypto) ExternalIdFor(subject string, actor string, entity types.LegalEntity) ([]byte, error) {
	if len(strings.TrimSpace(subject)) == 0 {
		return nil, ErrMissingSubject
	}

	if len(strings.TrimSpace(actor)) == 0 {
		return nil, ErrMissingActor
	}

	pk, err := client.Storage.GetPrivateKey(entity)
	if err != nil {
		return nil, err
	}

	// Create a new HMAC
	h := hmac.New(sha256.New, pk.D.Bytes())
	h.Write([]byte(subject))
	h.Write([]byte(actor))

	return h.Sum(nil), nil
}

// SignFor signs a piece of data for a legal entity. This requires the private key for the legal entity to be present.
// It is expected that the plain data is given. It uses the SHA256 hashing function
// todo: SHA_256?
func (client *Crypto) SignFor(data []byte, legalEntity types.LegalEntity) ([]byte, error) {
	// random
	rng := rand.Reader

	rsaPrivateKey, err := client.Storage.GetPrivateKey(legalEntity)
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

// KeyExistsFor checks storage for an entry for the given legal entity and returns true if it exists
func (client *Crypto) KeyExistsFor(legalEntity types.LegalEntity) bool {
	return client.Storage.KeyExistsFor(legalEntity)
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
func (client *Crypto) PublicKeyInPEM(legalEntity types.LegalEntity) (string, error) {
	pubKey, err := client.Storage.GetPublicKey(legalEntity)

	if err != nil {
		return "", err
	}

	return PublicKeyToPem(pubKey)
}

// PublicKeyInJWK loads the key from storage and wraps it in a Key format. Supports RSA, ECDSA and Symmetric style keys
func (client *Crypto) PublicKeyInJWK(legalEntity types.LegalEntity) (jwk.Key, error) {
	pubKey, err := client.Storage.GetPublicKey(legalEntity)

	if err != nil {
		return nil, err
	}

	return jwk.New(pubKey)
}

// SignJwtFor creates a signed JWT given a legalEntity and map of claims
func (client *Crypto) SignJwtFor(claims map[string]interface{}, legalEntity types.LegalEntity) (string, error) {
	rsaPrivateKey, err := client.Storage.GetPrivateKey(legalEntity)

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

func (client Crypto) JWSSignEphemeral(payload []byte, ca types.LegalEntity, csr x509.CertificateRequest, signingTime time.Time) ([]byte, error) {
	// Generate ephemeral key and certificate
	entityPrivateKey, err := client.generateKeyPair()
	if err != nil {
		return nil, err
	}
	csr.PublicKey = &entityPrivateKey.PublicKey
	asn1Cert, err := client.signCertificate(&csr, ca, CertificateProfile{
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
		JWSx509CertChain: marshalX509CertChain([]*x509.Certificate{certificate}),
	}
	return jws.Sign(payload, jwsAlgorithm, entityPrivateKey, jws.WithHeaders(&headers))
}

type CertificateVerifier interface {
	// Verify verifies the given certificate. The validity of the certificate is checked against the given moment in time.
	Verify(*x509.Certificate, time.Time) error
}

func (client *Crypto) VerifyJWS(signature []byte, signingTime time.Time, certVerifier CertificateVerifier) ([]byte, error) {
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
	certChain, err := GetX509ChainFromHeaders(sig.ProtectedHeaders())
	if err != nil {
		return nil, errors2.Wrap(err, ErrInvalidCertChain.Error())
	}
	if len(certChain) == 0 {
		return nil, fmt.Errorf("JWK doesn't contain X509 chain header (%s) header", jws.X509CertChainKey)
	}
	signingCert := certChain[0]
	// Check key strength. Cast should be safe since we checked the algorithm.
	signingPubKey, ok := signingCert.PublicKey.(*rsa.PublicKey)
	if !ok || signingPubKey.Size()*8 < MinKeySize {
		return nil, ErrInvalidKeySize
	}
	// Check certificate is trusted
	if err := certVerifier.Verify(signingCert, signingTime); err != nil {
		return nil, errors2.Wrap(err, ErrCertificateNotTrusted.Error())
	}
	// Check if the KeyUsage of the certificate is applicable for signing
	if signingCert.KeyUsage&x509.KeyUsageDigitalSignature != x509.KeyUsageDigitalSignature {
		return nil, errors.New("certificate is not meant for signing (keyUsage != digitalSignature)")
	}
	// TODO: CRL checking
	return jws.Verify(signature, sig.ProtectedHeaders().Algorithm(), signingCert.PublicKey)
}

// Decrypt a piece of data for the given legalEntity. It loads the private key from the storage and decrypts the cipherText.
// It returns an error if the given legalEntity does not have a private key.
func (client *Crypto) decryptCipherTextFor(cipherText []byte, legalEntity types.LegalEntity) ([]byte, error) {

	key, err := client.Storage.GetPrivateKey(legalEntity)

	if err != nil {
		return nil, err
	}

	plainText, err := decryptWithPrivateKey(cipherText, key)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Encrypt a piece of data for a legalEntity. Usually encryptPlainTextWith will be used with a public key of a different (unknown) legalEntity.
// It returns an error if the given legalEntity does not have a private key.
func (client *Crypto) encryptPlainTextFor(plaintext []byte, legalEntity types.LegalEntity) ([]byte, error) {

	publicKey, err := client.Storage.GetPublicKey(legalEntity)

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

func (client *Crypto) logger() *logrus.Entry {
	if client._logger == nil {
		client._logger = logrus.StandardLogger().WithField("module", ModuleName)
	}
	return client._logger
}
