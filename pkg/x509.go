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
	"crypto/rand"
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
	return client.Storage.SaveCertificate(key, certificate.Raw)
}

func (client *Crypto) SelfSignVendorCACertificate(name string) (*x509.Certificate, error) {
	identity := core.NutsConfig().VendorID()
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
	identity := core.NutsConfig().VendorID()
	log.Logger().Infof("Generating CSR for Vendor CA certificate (for current vendor: %s, name: %s)", identity, name)
	if pkcs10, _, err := client.generateVendorCACSR(name, identity); err != nil {
		return nil, err
	} else {
		return pkcs10, nil
	}
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
