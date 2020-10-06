package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/stretchr/testify/assert"
)

func TestVendorCertificateRequest(t *testing.T) {
	abc, _ := core.NewPartyID("test", "abc")
	zero, _ := core.ParsePartyID("::")

	t.Run("ok", func(t *testing.T) {
		csr, err := VendorCertificateRequest(abc, "def", "xyz", "care")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, csr)
	})
	t.Run("ok - optional params", func(t *testing.T) {
		csr, err := VendorCertificateRequest(abc, "def", "", "healthcare")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, csr)
	})
	t.Run("err - no domain", func(t *testing.T) {
		_, err := VendorCertificateRequest(abc, "def", "", "")
		assert.EqualError(t, err, "missing domain")
	})
	t.Run("error: no ID", func(t *testing.T) {
		_, err := VendorCertificateRequest(zero, "hello", "", "healthcare")
		assert.EqualError(t, err, "missing vendor identifier")
	})
	t.Run("error: no name", func(t *testing.T) {
		_, err := VendorCertificateRequest(abc, "", "", "healthcare")
		assert.EqualError(t, err, "missing vendor name")
	})
}

func TestCSRFromVendorCA(t *testing.T) {
	ca := generateTestCA()
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("fails for missing public key", func(t *testing.T) {
		_, err := CSRFromVendorCA(ca, "qualifier", "qualifier", nil)

		assert.Error(t, err)
	})

	t.Run("fails for missing CA", func(t *testing.T) {
		_, err := CSRFromVendorCA(nil, "qualifier", "qualifier", sk.PublicKey)

		assert.Error(t, err)
	})

	t.Run("fails for missing replacement qualifier", func(t *testing.T) {
		_, err := CSRFromVendorCA(ca, "qualifier", "", sk.PublicKey)

		assert.Error(t, err)
	})

	t.Run("sets the right common name", func(t *testing.T) {
		csr, err := CSRFromVendorCA(ca, "CA", "qualifier", sk.PublicKey)

		if assert.NoError(t, err) {
			assert.Equal(t, "CN qualifier", csr.Subject.CommonName)
		}
	})

	t.Run("does not alter the common name", func(t *testing.T) {
		csr, err := CSRFromVendorCA(ca, "", "qualifier", sk.PublicKey)

		if assert.NoError(t, err) {
			assert.Equal(t, "CN CA qualifier", csr.Subject.CommonName)
		}
	})

	t.Run("sets the right extensions", func(t *testing.T) {
		csr, err := CSRFromVendorCA(ca, "", "qualifier", sk.PublicKey)

		if assert.NoError(t, err) {
			if assert.Len(t, csr.ExtraExtensions, 2) {
				v, _ := UnmarshalOtherSubjectAltName(OIDNutsVendor, csr.ExtraExtensions[0].Value)
				assert.Equal(t, "vendor", v)
				d, _ := UnmarshalNutsDomain(csr.ExtraExtensions[1].Value)
				assert.Equal(t, "test", d)
			}
		}
	})
}

func generateTestCA() *x509.Certificate {
	sn, _ := SerialNumber()
	notBefore := time.Now()
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	subjectAltName, _ := MarshalOtherSubjectAltName(OIDNutsVendor, "vendor")
	domainData, _ := MarshalNutsDomain("test")
	extensions := []pkix.Extension{
		{Id: OIDSubjectAltName, Critical: false, Value: subjectAltName},
		{Id: OIDNutsDomain, Critical: false, Value: domainData},
	}

	template := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Country:      []string{"NL"},
			Organization: []string{"Test"},
			CommonName:   "CN CA",
		},
		PublicKey:             privKey.PublicKey,
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, 4),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions:       extensions,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	data, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		panic(err)
	}
	certificate, err := x509.ParseCertificate(data)
	return certificate
}
