package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"

	asn12 "github.com/nuts-foundation/nuts-crypto/pkg/asn1"
	core "github.com/nuts-foundation/nuts-go-core"
)

var OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
var OIDNuts = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54851}
var OIDNutsVendor = asn12.OIDAppend(OIDNuts, 4)
var OIDNutsDomain = asn12.OIDAppend(OIDNuts, 3)

// VendorCertificateRequest creates a CertificateRequest template for issuing a vendor certificate.
//   vendorID:      URN-OID-encoded ID of the vendor
//   vendorName:    Name of the vendor
//   qualifier:     (optional) Qualifier for the certificate, which will be postfixed to Subject.CommonName
//   domain:        Domain the vendor operates in, e.g. "healthcare"
func VendorCertificateRequest(vendorID core.PartyID, vendorName string, qualifier string, domain string) (*x509.CertificateRequest, error) {
	if vendorID.IsZero() {
		return nil, errors.New("missing vendor identifier")
	}
	if vendorName == "" {
		return nil, errors.New("missing vendor name")
	}
	if domain == "" {
		return nil, errors.New("missing domain")
	}
	// The supplied vendorID is prefixed with the type (URN+OID), which is also specified in the ASN.1 structure.
	// Thus we should just take the value part (everything after the last colon) from the vendorID.
	subjectAltName, err := MarshalOtherSubjectAltName(OIDNutsVendor, vendorID.Value())
	if err != nil {
		return nil, err
	}
	extensions := []pkix.Extension{
		{Id: OIDSubjectAltName, Critical: false, Value: subjectAltName},
	}

	domainData, err := MarshalNutsDomain(domain)
	if err != nil {
		return nil, err
	}
	extensions = append(extensions, pkix.Extension{Id: OIDNutsDomain, Critical: false, Value: domainData})

	commonName := vendorName
	if qualifier != "" {
		commonName += " " + qualifier
	}
	return &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"NL"},
			Organization: []string{vendorName},
			CommonName:   commonName,
		},
		ExtraExtensions: extensions,
	}, nil
}

// CSRFromVendorCA generates a CSR based upon the VendorCA. It copies any extensions needed as well as the O and C
// The common name is appended with the qualifier.
func CSRFromVendorCA(ca *x509.Certificate, qualifier string, publicKey interface{}) (*x509.CertificateRequest, error) {
	if ca == nil {
		return nil, errors.New("missing vendor CA")
	}

	if strings.TrimSpace(qualifier) == "" {
		return nil, errors.New("missing qualifier")
	}

	if publicKey == nil {
		return nil, errors.New("missing public key")
	}

	// extract SAN and Domain extensions
	extensions := []pkix.Extension{}

	for _, e := range ca.Extensions {
		if e.Id.Equal(OIDNutsDomain) || e.Id.Equal(OIDSubjectAltName) {
			extensions = append(extensions, e)
		}
	}

	return &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      ca.Subject.Country,
			Organization: ca.Subject.Organization,
			CommonName:   fmt.Sprintf("%s %s", ca.Subject.CommonName, qualifier),
		},
		PublicKey:       publicKey,
		ExtraExtensions: extensions,
	}, nil
}
