/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-crypto/log"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	errors2 "github.com/pkg/errors"
)

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

// TLSCertificateValidityInDays holds the number of days issued TLS certificates are valid
const TLSCertificateValidityInDays = 365

// SigningCertificateValidityInDays holds the number of days issued signing certificates are valid
const SigningCertificateValidityInDays = 365

// rfc003ValidityInDays is the number of days a certificate is valid according to Nuts RFC003
const rfc003ValidityInDays = 4

// rfc003SigningCertificateProfile is a x509.CertificateProfile according to RFC003: signing the JWT bearer token
var rfc003SigningCertificateProfile = CertificateProfile{
	KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	NumDaysValid: rfc003ValidityInDays,
}

// rfc003TLSCertificateProfile is a x509.CertificateProfile according to RFC003/RFC008: setting up the TLS connection between nodes
var rfc003TLSCertificateProfile = CertificateProfile{
	KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	NumDaysValid: rfc003ValidityInDays,
}

// vendorCACertificateDaysValid holds the number of days self-signed Vendor CA certificates are valid
const vendorCACertificateDaysValid = 1095

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
	identity := core.NutsConfig().VendorID()
	log.Logger().Infof("Storing CA certificate for: %s", identity)

	key := types.KeyForEntity(types.LegalEntity{URI: identity.String()})
	if !client.Storage.PrivateKeyExists(key) {
		return fmt.Errorf("private key not present for key: %s", key)
	}

	if publicKey, err := client.Storage.GetPublicKey(key); err != nil {
		return err
	} else if !reflect.DeepEqual(publicKey, certificate.PublicKey) {
		return fmt.Errorf("public key in certificate does not match stored private key (key: %s)", key)
	}

	// check ExtKeyUsage
	expectedEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	found := 0
	for _, exp := range expectedEKU {
		for _, eku := range certificate.ExtKeyUsage {
			if exp == eku {
				found++
			}
		}
	}
	if found != 2 {
		return fmt.Errorf("certificate does not define ExtKeyUsage: ClientAuth, ServerAuth")
	}
	return client.Storage.SaveCertificate(key, certificate.Raw)
}

func (client *Crypto) SelfSignVendorCACertificate(name string) (*x509.Certificate, error) {
	identity := core.NutsConfig().VendorID()
	var csr *x509.CertificateRequest
	csrAsASN1, privateKey, err := client.generateVendorCACSR(name, identity)
	if err != nil {
		return nil, err
	}
	if csr, err = x509.ParseCertificateRequest(csrAsASN1); err != nil {
		return nil, errors2.Wrap(err, "unable to parse CSR")
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtraExtensions:       csr.Extensions,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	log.Logger().Infof("Self-signing Vendor CA certificate for vendor: %s", name)
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, privateKey)
	if err != nil {
		return nil, errors2.Wrap(err, "unable to create certificate")
	}

	return x509.ParseCertificate(certificate)
}

func (client *Crypto) GenerateVendorCACSR(name string) ([]byte, error) {
	identity := core.NutsConfig().VendorID()
	log.Logger().Infof("Generating CSR for Vendor CA certificate (for current vendor: %s, name: %s)", identity, name)
	pkcs10, _, err := client.generateVendorCACSR(name, identity)
	if err != nil {
		return nil, err
	}
	return pkcs10, nil
}

func (client *Crypto) generateVendorCACSR(name string, identity core.PartyID) ([]byte, crypto.PrivateKey, error) {
	if strings.TrimSpace(name) == "" {
		return nil, nil, errors.New("invalid name")
	}
	key := types.KeyForEntity(types.LegalEntity{URI: identity.String()})
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
	csr, err := cert.VendorCertificateRequest(identity, name, CACertificateQualifier, "healthcare") // TODO: Domain is now hardcoded
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

// SignTLSCertificate creates a TLS Client certificate. It uses the Vendor CA to sign.
// the resulting certificate is valid for 4 days.
func (client *Crypto) SignTLSCertificate(key crypto.PublicKey) (*x509.Certificate, error) {
	return client.generateVendorTLSCertificate(key)
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

// validatePublicKeyRequirements checks if the given public key is a ecdsa or rsa public key and validates minimum length
func validatePublicKeyRequirements(publicKey crypto.PublicKey) error {
	// the current version of the used JWT lib doesn't support the crypto.Signer interface. The 4.0.0 version will.
	switch publicKey.(type) {
	case *rsa.PublicKey:
		rpk := publicKey.(*rsa.PublicKey)
		if rpk.N.BitLen() < MinRSAKeySize {
			return ErrInvalidKeySize
		}
	case *ecdsa.PublicKey:
		epk := publicKey.(*ecdsa.PublicKey)
		switch epk.Params().BitSize {
		case 256:
		case 384:
		case 521:
		default:
			return ErrInvalidKeySize
		}
	default:
		return ErrInvalidAlgorithm
	}
	return nil
}

// generateVendorCertificate holds common logic for singing TLS and Signing certificates
// only ecdsa and rsa pub keys are supported
func (client *Crypto) generateVendorCertificate(publicKey crypto.PublicKey, qualifier string, profile CertificateProfile) (*x509.Certificate, error) {
	entity := vendorEntity()
	log.Logger().Debugf("Generating '%s' certificate for entity: %s", qualifier, entity)

	if err := validatePublicKeyRequirements(publicKey); err != nil {
		return nil, err
	}

	caKey := types.KeyForEntity(entity)
	caCertificate, err := client.Storage.GetCertificate(caKey)
	if err != nil || caCertificate == nil {
		return nil, fmt.Errorf("unable to retrieve CA certificate %s: %v", caKey, err)
	}
	if len(caCertificate.Subject.Organization) == 0 {
		return nil, fmt.Errorf("subject of CA certificate %s doesn't contain 'O' component", caKey)
	}
	if len(caCertificate.Subject.Country) == 0 {
		return nil, fmt.Errorf("subject of CA certificate %s doesn't contain 'C' component", caKey)
	}

	var certificate *x509.Certificate

	csr, err := cert.CSRFromVendorCA(caCertificate, CACertificateQualifier, qualifier, publicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to construct CSR: %w", err)
	}

	// in this case we don't serialize the CSR so the extra extensions need to be copied to the extensions
	csr.Extensions = csr.ExtraExtensions

	certificateAsBytes, err := client.signCertificate(csr, caKey, profile, false)
	if err != nil {
		return nil, errors2.Wrapf(err, "unable to generate %s certificate %s", qualifier, caKey)
	}
	certificate, err = x509.ParseCertificate(certificateAsBytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func (client *Crypto) generateVendorTLSCertificate(publicKey crypto.PublicKey) (*x509.Certificate, error) {
	return client.generateVendorCertificate(publicKey, TLSCertificateQualifier, rfc003TLSCertificateProfile)
}

func (client *Crypto) generateVendorEphemeralSigningCertificate() (*x509.Certificate, crypto.Signer, error) {
	var privateKey *ecdsa.PrivateKey
	var err error
	if privateKey, err = generateECKeyPair(); err != nil {
		return nil, nil, errors2.Wrapf(err, "unable to generate key pair for new %s certificate", OAuthCertificateQualifier)
	}
	certificate, err := client.generateVendorCertificate(&privateKey.PublicKey, OAuthCertificateQualifier, rfc003SigningCertificateProfile)
	if err != nil {
		return nil, nil, err
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
