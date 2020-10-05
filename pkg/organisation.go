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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"

	"github.com/nuts-foundation/nuts-crypto/log"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	errors2 "github.com/pkg/errors"
)

// This file contains logic specific for organisation level certificates
// Newer RFC's no longer use organisation level certificates, only node level.

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
