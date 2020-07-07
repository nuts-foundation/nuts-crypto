package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	asn12 "github.com/nuts-foundation/nuts-crypto/pkg/asn1"
	"strings"
)


var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
var oidNuts = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54851}
var oidNutsVendor = asn12.OIDAppend(oidNuts, 4)
var oidNutsDomain = asn12.OIDAppend(oidNuts, 3)

// VendorCertificateRequest creates a CertificateRequest template for issuing a vendor certificate.
//   vendorID:      URN-OID-encoded ID of the vendor
//   vendorName:    Name of the vendor
//   qualifier:     (optional) Qualifier for the certificate, which will be postfixed to Subject.CommonName
//   domain:        Domain the vendor operates in, e.g. "healthcare"
func VendorCertificateRequest(vendorID string, vendorName string, qualifier string, domain string) (*x509.CertificateRequest, error) {
	if vendorID == "" {
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
	vendorIDParts := strings.Split(vendorID, ":")
	subjectAltName, err := MarshalOtherSubjectAltName(oidNutsVendor, vendorIDParts[len(vendorIDParts) - 1])
	if err != nil {
		return nil, err
	}
	extensions := []pkix.Extension{
		{Id: oidSubjectAltName, Critical: false, Value: subjectAltName},
	}

	domainData, err := MarshalNutsDomain(domain)
	if err != nil {
		return nil, err
	}
	extensions = append(extensions, pkix.Extension{Id: oidNutsDomain, Critical: false, Value: domainData})

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
