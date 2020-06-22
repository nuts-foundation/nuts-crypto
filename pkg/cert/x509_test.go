package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-crypto/test"
	"github.com/stretchr/testify/assert"
)

func Test_serialNumberUniqueness(t *testing.T) {
	r := make(map[string]bool, 0)
	for i := 0; i < 100000; i++ {
		serial, err := SerialNumber()
		if !assert.NoError(t, err) {
			return
		}
		if r[serial.String()] {
			assert.Failf(t, "duplicate found", "serial: %d", serial)
			return
		}
		r[serial.String()] = true
	}
}

func TestGetActiveCertificates(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	t.Run("no keys", func(t *testing.T) {
		certificates := GetActiveCertificates(make([]interface{}, 0), time.Now())
		assert.Empty(t, certificates)
	})
	t.Run("no certificate for key", func(t *testing.T) {
		key, _ := jwk.New(rsaKey)
		certificates := GetActiveCertificates([]interface{}{jwkToMap(key)}, time.Now())
		assert.Empty(t, certificates)
	})
	t.Run("single entry", func(t *testing.T) {
		certBytes := test.GenerateCertificateEx(time.Now().AddDate(0, 0, -1), 2, rsaKey)
		cert, err := x509.ParseCertificate(certBytes)
		if !assert.NoError(t, err) {
			return
		}
		key, _ := CertificateToJWK(cert)
		certs := GetActiveCertificates([]interface{}{jwkToMap(key)}, time.Now())
		assert.Len(t, certs, 1)
	})
	t.Run("multiple entries", func(t *testing.T) {
		// Certificates:
		// cert1 is expired
		// cert2 is valid
		// cert3 is valid, and longer than cert2
		// cert4 is not valid yet
		// Expected result: cert3, cert2
		cert1, _ := x509.ParseCertificate(test.GenerateCertificateEx(time.Now().AddDate(0, 0, -5), 1, rsaKey))
		cert2, _ := x509.ParseCertificate(test.GenerateCertificateEx(time.Now().AddDate(0, 0, -1), 3, rsaKey))
		cert3, _ := x509.ParseCertificate(test.GenerateCertificateEx(time.Now().AddDate(0, 0, -1), 4, rsaKey))
		cert4, _ := x509.ParseCertificate(test.GenerateCertificateEx(time.Now().AddDate(0, 0, 1), 1, rsaKey))
		key1, _ := jwk.New(rsaKey)
		key1.Set(jwk.X509CertChainKey, base64.StdEncoding.EncodeToString(cert1.Raw))
		key2, _ := jwk.New(rsaKey)
		key2.Set(jwk.X509CertChainKey, base64.StdEncoding.EncodeToString(cert2.Raw))
		key3, _ := jwk.New(rsaKey)
		key3.Set(jwk.X509CertChainKey, base64.StdEncoding.EncodeToString(cert3.Raw))
		key4, _ := jwk.New(rsaKey)
		key4.Set(jwk.X509CertChainKey, base64.StdEncoding.EncodeToString(cert4.Raw))
		certs := GetActiveCertificates([]interface{}{jwkToMap(key1), jwkToMap(key2), jwkToMap(key3), jwkToMap(key4)}, time.Now())
		if !assert.Len(t, certs, 2) {
			return
		}
		assert.Equal(t, cert3.Raw, certs[0].Raw, "Expected certs[0] to be equal to cert3")
		assert.Equal(t, cert2.Raw, certs[1].Raw, "Expected certs[1] to be equal to cert2")
	})
	t.Run("chain empty", func(t *testing.T) {
		key, _ := jwk.New(rsaKey)
		jwkAsMap := jwkToMap(key)
		jwkAsMap["x5c"] = []string{}
		certs := GetActiveCertificates([]interface{}{jwkAsMap}, time.Now())
		assert.Len(t, certs, 0)
	})
}

func jwkToMap(key jwk.Key) map[string]interface{} {
	m, _ := JwkToMap(key)
	keyAsJSON, _ := json.MarshalIndent(m, "", "  ")
	j := map[string]interface{}{}
	json.Unmarshal(keyAsJSON, &j)
	return j
}

func TestMarshalOtherSubjectAltName(t *testing.T) {
	bytes, err := MarshalOtherSubjectAltName(asn1.ObjectIdentifier{1, 2}, "Foobar")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, []byte{0x30, 0xf, 0xa0, 0xd, 0x6, 0x1, 0x2a, 0xa0, 0x8, 0xc, 0x6, 0x46, 0x6f, 0x6f, 0x62, 0x61, 0x72}, bytes)
}

func TestUnmarshalOtherSubjectAltName(t *testing.T) {
	input := []byte{0x30, 0xf, 0xa0, 0xd, 0x6, 0x1, 0x2a, 0xa0, 0x8, 0xc, 0x6, 0x46, 0x6f, 0x6f, 0x62, 0x61, 0x72}
	t.Run("ok", func(t *testing.T) {
		name, err := UnmarshalOtherSubjectAltName(asn1.ObjectIdentifier{1, 2}, input)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "Foobar", name)
	})
	t.Run("ok - not found", func(t *testing.T) {
		name, err := UnmarshalOtherSubjectAltName(asn1.ObjectIdentifier{1}, input)
		if !assert.NoError(t, err) {
			return
		}
		assert.Empty(t, name)
	})
	t.Run("error", func(t *testing.T) {
		name, err := UnmarshalOtherSubjectAltName(asn1.ObjectIdentifier{1}, []byte{0x30, 0xf, 0xa0, 0xd, 0x6, 0x1, 0xa0, 0x8, 0xc, 0x6, 0x46, 0x6f, 0x6f, 0x62, 0x61, 0x72})
		assert.Error(t, err)
		assert.Empty(t, name)
	})
}

func TestMarshalNutsDomain(t *testing.T) {
	data, err := MarshalNutsDomain("healthcare")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, []byte{0xc, 0xa, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x63, 0x61, 0x72, 0x65}, data)
}

func TestUnmarshalNutsDomain(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		domain, err := UnmarshalNutsDomain([]byte{0xc, 0xa, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x63, 0x61, 0x72, 0x65})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "healthcare", domain)
	})
	t.Run("error", func(t *testing.T) {
		domain, err := UnmarshalNutsDomain([]byte{0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x63, 0x61, 0x72, 0x65})
		assert.Error(t, err)
		assert.Empty(t, domain)
	})
}
