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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-crypto/test"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/stretchr/testify/assert"
)

type poolCertVerifier struct {
	pool *x509.CertPool
}

func (n poolCertVerifier) Pool() *x509.CertPool {
	return n.pool
}

func (n *poolCertVerifier) AddCertificate(certificate *x509.Certificate) error {
	n.pool.AddCert(certificate)
	return nil
}

func (n poolCertVerifier) GetRoots(t time.Time) []*x509.Certificate {
	panic("implement me")
}

func (n poolCertVerifier) GetCertificates(i [][]*x509.Certificate, t time.Time, b bool) [][]*x509.Certificate {
	panic("implement me")
}

func (n poolCertVerifier) Verify(cert *x509.Certificate, moment time.Time) error {
	_, err := n.VerifiedChain(cert, moment)
	return err
}

func (n poolCertVerifier) VerifiedChain(cert *x509.Certificate, moment time.Time) ([][]*x509.Certificate, error) {
	if n.pool == nil {
		return nil, nil
	}
	return cert.Verify(x509.VerifyOptions{Roots: n.pool, CurrentTime: moment})
}

func TestCrypto_GenerateVendorCACSR(t *testing.T) {
	client := createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		csrAsBytes, err := client.GenerateVendorCACSR("BecauseWeCare B.V.")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, csrAsBytes)
		// Verify result is a valid PKCS10 CSR
		csr, err := x509.ParseCertificateRequest(csrAsBytes)
		if !assert.NoError(t, err) {
			return
		}
		// Verify signature
		err = csr.CheckSignature()
		if !assert.NoError(t, err) {
			return
		}

		t.Run("verify subject", func(t *testing.T) {
			assert.Equal(t, "CN=BecauseWeCare B.V. CA,O=BecauseWeCare B.V.,C=NL", csr.Subject.String())
		})
		t.Run("verify VendorID SAN", func(t *testing.T) {
			extension, err := CertificateRequest(*csr).getUniqueExtension("2.5.29.17")
			assert.NoError(t, err)
			assert.Equal(t, []byte{0x30, 0x14, 0xa0, 0x12, 0x6, 0x9, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x83, 0xac, 0x43, 0x4, 0xa0, 0x5, 0xc, 0x3, 0x31, 0x32, 0x33}, extension.Value)
		})
		t.Run("verify Domain extension", func(t *testing.T) {
			extension, err := CertificateRequest(*csr).getUniqueExtension("1.3.6.1.4.1.54851.3")
			assert.NoError(t, err)
			assert.Equal(t, "healthcare", strings.TrimSpace(string(extension.Value)))
		})
	})
	t.Run("ok - key exists", func(t *testing.T) {
		client.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{core.NutsConfig().Identity()}), false)
		csr, err := client.GenerateVendorCACSR("BecauseWeCare B.V.")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, csr)
		// Verify result is a valid PKCS10 CSR
		parsedCSR, err := x509.ParseCertificateRequest(csr)
		if !assert.NoError(t, err) {
			return
		}
		// Verify signature
		err = parsedCSR.CheckSignature()
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("error - invalid name", func(t *testing.T) {
		csr, err := client.GenerateVendorCACSR("   ")
		assert.Nil(t, csr)
		assert.EqualError(t, err, "invalid name")
	})
}

func TestCrypto_SelfSignVendorCACertificate(t *testing.T) {
	client := createCrypto(t)
	t.Run("ok", func(t *testing.T) {
		certificate, err := client.SelfSignVendorCACertificate("BecauseWeCare B.V.")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		t.Run("verify subject & issuer", func(t *testing.T) {
			assert.Equal(t, "CN=BecauseWeCare B.V. CA,O=BecauseWeCare B.V.,C=NL", certificate.Subject.String())
			assert.Equal(t, "CN=BecauseWeCare B.V. CA,O=BecauseWeCare B.V.,C=NL", certificate.Issuer.String())
		})
		t.Run("verify VendorID SAN", func(t *testing.T) {
			extension, err := getUniqueExtension("2.5.29.17", certificate.Extensions)
			assert.NoError(t, err)
			assert.Equal(t, []byte{0x30, 0x14, 0xa0, 0x12, 0x6, 0x9, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x83, 0xac, 0x43, 0x4, 0xa0, 0x5, 0xc, 0x3, 0x31, 0x32, 0x33}, extension.Value)
		})
		t.Run("verify Domain extension", func(t *testing.T) {
			extension, err := getUniqueExtension("1.3.6.1.4.1.54851.3", certificate.Extensions)
			assert.NoError(t, err)
			assert.Equal(t, "healthcare", strings.TrimSpace(string(extension.Value)))
		})
	})
}

func TestCrypto_StoreVendorCACertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	t.Run("ok - private key exists", func(t *testing.T) {
		client.GenerateKeyPair(key, false)
		privateKey, _ := client.GetPrivateKey(key)
		certificateAsBytes := test.GenerateCertificate(time.Now(), 1, privateKey)
		certificate, _ := x509.ParseCertificate(certificateAsBytes)
		err := client.StoreVendorCACertificate(certificate)
		assert.NoError(t, err)
	})
	t.Run("error - private key does not exist", func(t *testing.T) {
		client := createCrypto(t)
		createCrypto(t)

		privateKey, _ := client.generateKeyPair()
		certificateAsBytes := test.GenerateCertificate(time.Now(), 1, privateKey)
		certificate, _ := x509.ParseCertificate(certificateAsBytes)
		err := client.StoreVendorCACertificate(certificate)
		assert.EqualError(t, err, "private key not present for key: [urn:oid:1.3.6.1.4.1.54851.4:123|]")
	})
	t.Run("error - existing private key differs", func(t *testing.T) {
		client.GenerateKeyPair(key, true)
		privateKey, _ := client.GetPrivateKey(key)
		certificateAsBytes := test.GenerateCertificate(time.Now(), 1, privateKey)
		certificate, _ := x509.ParseCertificate(certificateAsBytes)
		client.GenerateKeyPair(key, true)
		err := client.StoreVendorCACertificate(certificate)
		assert.EqualError(t, err, "public key in certificate does not match stored private key (key: [urn:oid:1.3.6.1.4.1.54851.4:123|])")
	})
	t.Run("error - certificate is nil", func(t *testing.T) {
		err := client.StoreVendorCACertificate(nil)
		assert.EqualError(t, err, "certificate is nil")
	})
}

func TestCrypto_GetSigningCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 365*3)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)

	t.Run("ok - non existent", func(t *testing.T) {
		certificate, privateKey, err := client.GetSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
	t.Run("ok - exists", func(t *testing.T) {
		_, _, err := client.RenewSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		certificate, privateKey, err := client.GetSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)
	})
	t.Run("ok - exists but expired", func(t *testing.T) {
		privateKey, err := client.generateAndStoreKeyPair(key.WithQualifier(SigningCertificateQualifier), true)
		if !assert.NoError(t, err) {
			return
		}
		certificateAsASN1 := test.GenerateCertificate(time.Now().AddDate(-1, 0, 0), 1, privateKey)
		client.Storage.SaveCertificate(key.WithQualifier(SigningCertificateQualifier), certificateAsASN1)
		certificate, pk, err := client.GetSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, certificate)
		assert.Nil(t, pk)
	})
	t.Run("error - exists, missing private key", func(t *testing.T) {
		entity2 := types.LegalEntity{"foobar2"}
		key2 := types.KeyForEntity(entity2)
		privateKey, _ := client.generateKeyPair()
		certificateAsASN1 := test.GenerateCertificate(time.Now(), 1, privateKey)
		client.Storage.SaveCertificate(key2.WithQualifier(SigningCertificateQualifier), certificateAsASN1)
		certificate, pk, err := client.GetSigningCertificate(entity2)
		assert.Contains(t, err.Error(), "unable to retrieve private key for certificate: [foobar2|sign]: could not open entry [foobar2|sign] with filename")
		assert.Nil(t, certificate)
		assert.Nil(t, pk)
	})
}

func TestCrypto_RenewSigningCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 365*3)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)

	t.Run("ok", func(t *testing.T) {
		certificate, privateKey, err := client.RenewSigningCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)
	})
}

func TestCrypto_issueSubCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 1)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)
	t.Run("ok", func(t *testing.T) {
		certificate, privateKey, err := client.issueSubCertificate(entity, "test", CertificateProfile{})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)

		// Verify SAN is copied from CA certificate
		var san pkix.Extension
		for _, extension := range certificate.Extensions {
			if cert.OIDSubjectAltName.Equal(extension.Id) {
				san = extension
			}
		}
		assert.False(t, san.Id.String() == "", "SAN not found")
		altName, err := cert.UnmarshalOtherSubjectAltName(cert.OIDNutsVendor, san.Value)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "Foobar", altName)
	})
	t.Run("error - CA certificate not found", func(t *testing.T) {
		certificate, privateKey, err := client.issueSubCertificate(types.LegalEntity{"foobar"}, "test", CertificateProfile{})
		assert.Contains(t, err.Error(), "unable to retrieve CA certificate [foobar|]: could not open entry [foobar|] with filename")
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
	t.Run("error - qualifier not set", func(t *testing.T) {
		_, _, err := client.issueSubCertificate(types.LegalEntity{}, "", CertificateProfile{})
		assert.EqualError(t, err, "missing qualifier")
	})
	t.Run("error - CA certificate subject missing country", func(t *testing.T) {
		_, _ = selfSignCACertificateEx(client, key, pkix.Name{
			Organization: []string{"Zorg Inc."},
		}, time.Now(), 1)
		certificate, privateKey, err := client.issueSubCertificate(entity, "test", CertificateProfile{})
		assert.EqualError(t, err, "subject of CA certificate [urn:oid:1.3.6.1.4.1.54851.4:123|] doesn't contain 'C' component")
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
	t.Run("error - CA certificate subject missing org", func(t *testing.T) {
		_, _ = selfSignCACertificateEx(client, key, pkix.Name{
			Country: []string{"NL"},
		}, time.Now(), 1)
		certificate, privateKey, err := client.issueSubCertificate(entity, "test", CertificateProfile{})
		assert.EqualError(t, err, "subject of CA certificate [urn:oid:1.3.6.1.4.1.54851.4:123|] doesn't contain 'O' component")
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
}

func TestCrypto_GetTLSCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 365*3)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)

	t.Run("ok - non existent", func(t *testing.T) {
		certificate, privateKey, err := client.GetTLSCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, certificate)
		assert.Nil(t, privateKey)
	})
	t.Run("ok - exists", func(t *testing.T) {
		_, _, err := client.RenewTLSCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		certificate, privateKey, err := client.GetTLSCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)
	})
}

func TestCrypto_RenewTLSCertificate(t *testing.T) {
	client := createCrypto(t)
	createCrypto(t)

	client.GenerateKeyPair(key, false)
	caCertificate, err := selfSignCACertificateEx(client, key, pkix.Name{
		Country:      []string{"NL"},
		Organization: []string{"Zorg Inc."},
	}, time.Now(), 365*3)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, caCertificate)

	t.Run("ok", func(t *testing.T) {
		certificate, privateKey, err := client.RenewTLSCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, certificate)
		assert.NotNil(t, privateKey)

		// Verify SAN is copied from CA certificate
		var san pkix.Extension
		for _, extension := range certificate.Extensions {
			if cert.OIDSubjectAltName.Equal(extension.Id) {
				san = extension
			}
		}
		assert.False(t, san.Id.String() == "", "SAN not found")
		altName, err := cert.UnmarshalOtherSubjectAltName(cert.OIDNutsVendor, san.Value)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "Foobar", altName)
	})
	t.Run("ok - certificate already exists", func(t *testing.T) {

	})
}

func TestCrypto_SignCertificate(t *testing.T) {
	client := createCrypto(t)

	ca := key
	client.GenerateKeyPair(ca, false)
	caPrivateKey, _ := client.GetPrivateKey(ca)
	endEntityKey := types.KeyForEntity(types.LegalEntity{URI: "End Entity"})
	intermediateCaKey := types.KeyForEntity(types.LegalEntity{URI: "Intermediate CA"})

	roots := x509.NewCertPool()

	t.Run("self-sign CSR", func(t *testing.T) {
		certificate, err := selfSignCACertificate(client, ca)
		if !assert.NoError(t, err) {
			return
		}
		containsExtension := false
		for _, ext := range certificate.Extensions {
			if reflect.DeepEqual(ext, extension) {
				containsExtension = true
			}
		}
		assert.True(t, containsExtension, "certificate doesn't contain custom extension")

		assert.True(t, certificate.IsCA)
		assert.Equal(t, 1, certificate.MaxPathLen)
		assert.Equal(t, ca.Owner(), certificate.Subject.CommonName)
		assert.Equal(t, ca.Owner(), certificate.Issuer.CommonName)
		roots.AddCert(certificate)
		verify, err := certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		})
		assert.NoError(t, err)
		assert.NotNil(t, verify)
	})

	t.Run("sign CSR for end-entity under root CA", func(t *testing.T) {
		// Setup
		root, _ := selfSignCACertificate(client, ca)
		roots.AddCert(root)
		client.GenerateKeyPair(endEntityKey, false)
		endEntityPrivKey, _ := client.GetPrivateKey(endEntityKey)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: endEntityKey.Owner()},
		}
		csr, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, endEntityPrivKey)
		// Sign
		certBytes, err := client.SignCertificate(endEntityKey, ca, csr, CertificateProfile{
			NumDaysValid: 1,
		})
		// Verify
		if !assert.NoError(t, err) {
			return
		}
		certificate, err := x509.ParseCertificate(certBytes)
		if !assert.NoError(t, err) {
			return
		}
		assert.False(t, certificate.IsCA)
		assert.Equal(t, 0, certificate.MaxPathLen)
		assert.Equal(t, endEntityKey.Owner(), certificate.Subject.CommonName)
		assert.Equal(t, ca.Owner(), certificate.Issuer.CommonName)
		verify, err := certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, verify)
	})

	t.Run("error - signing certificate is not a CA certificate", func(t *testing.T) {
		// Certificate created by GenerateCertificate is not a CA certificate
		caCertificate := test.GenerateCertificate(time.Now(), 1, caPrivateKey)
		err := client.Storage.SaveCertificate(ca, caCertificate)
		if !assert.NoError(t, err) {
			return
		}
		csrTemplate := x509.CertificateRequest{
			Subject:   pkix.Name{CommonName: endEntityKey.Owner()},
			PublicKey: caPrivateKey.Public(),
		}
		certBytes, err := client.signCertificate(&csrTemplate, ca, CertificateProfile{}, false)
		assert.EqualError(t, err, "CA certificate validation failed: certificate is not an CA certificate")
		assert.Nil(t, certBytes)
	})

	t.Run("error - validity period must be within CA certificate", func(t *testing.T) {
		// Setup
		root, _ := selfSignCACertificate(client, ca)
		roots.AddCert(root)
		client.GenerateKeyPair(endEntityKey, false)
		endEntityPrivKey, _ := client.GetPrivateKey(endEntityKey)
		csrTemplate := x509.CertificateRequest{
			Subject:   pkix.Name{CommonName: endEntityKey.Owner()},
			PublicKey: endEntityPrivKey.Public(),
		}
		t.Run("not before", func(t *testing.T) {
			certBytes, err := client.signCertificate(&csrTemplate, ca, CertificateProfile{
				NumDaysValid: 1,
				notAfter:     root.NotAfter,
				notBefore:    time.Unix(root.NotBefore.Unix()-1000, 0),
			}, false)
			assert.Contains(t, err.Error(), "CA certificate validation failed: certificate validity")
			assert.Nil(t, certBytes)
		})
		t.Run("not after", func(t *testing.T) {
			certBytes, err := client.signCertificate(&csrTemplate, ca, CertificateProfile{
				NumDaysValid: 1,
				notBefore:    root.NotBefore,
				notAfter:     time.Unix(root.NotAfter.Unix()+1000, 0),
			}, false)
			assert.Contains(t, err.Error(), "CA certificate validation failed: certificate validity")
			assert.Nil(t, certBytes)
		})
	})

	t.Run("sign CSR for intermediate CA", func(t *testing.T) {
		// Setup
		root, _ := selfSignCACertificate(client, ca)
		roots.AddCert(root)
		client.GenerateKeyPair(intermediateCaKey, false)
		intermediateCaPrivKey, _ := client.GetPrivateKey(intermediateCaKey)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: intermediateCaKey.Owner()},
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, intermediateCaPrivKey)
		if !assert.NoError(t, err) {
			return
		}
		// Sign
		certBytes, err := client.SignCertificate(intermediateCaKey, ca, csr, CertificateProfile{
			IsCA:         true,
			NumDaysValid: 1,
		})
		// Verify
		if !assert.NoError(t, err) {
			return
		}
		certificate, err := x509.ParseCertificate(certBytes)
		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, certificate.IsCA)
		assert.False(t, certificate.MaxPathLenZero)
		assert.Equal(t, intermediateCaKey.Owner(), certificate.Subject.CommonName)
		assert.Equal(t, ca.Owner(), certificate.Issuer.CommonName)
		verify, err := certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, verify)
	})

	t.Run("invalid CSR: format", func(t *testing.T) {
		certificate, err := client.SignCertificate(endEntityKey, ca, []byte{1, 2, 3}, CertificateProfile{})
		assert.Contains(t, err.Error(), ErrUnableToParseCSR.Error())
		assert.Nil(t, certificate)
	})

	t.Run("invalid CSR: signature", func(t *testing.T) {
		client.GenerateKeyPair(key, false)
		endEntityPrivKey, _ := client.GetPrivateKey(endEntityKey)
		otherPrivKey, _ := client.GetPrivateKey(ca)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: endEntityKey.Owner()},
		}
		// Make this CSR invalid by providing a public key which doesn't match the private key
		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, opaquePrivateKey{
			signFn:    endEntityPrivKey.Sign,
			publicKey: otherPrivKey.Public(),
		})
		if !assert.NoError(t, err) {
			return
		}
		// Sign
		certificate, err := client.SignCertificate(endEntityKey, ca, csr, CertificateProfile{NumDaysValid: 1})
		assert.Contains(t, err.Error(), ErrCSRSignatureInvalid.Error())
		assert.Nil(t, certificate)
	})

	t.Run("unknown CA: private key missing", func(t *testing.T) {
		// Setup
		client := createCrypto(t)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: endEntityKey.Owner()},
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, caPrivateKey)
		if !assert.NoError(t, err) {
			return
		}
		// Sign
		certificate, err := client.SignCertificate(endEntityKey, types.KeyForEntity(types.LegalEntity{"foobar"}), csr, CertificateProfile{})
		// Verify
		assert.Contains(t, err.Error(), ErrUnknownCA.Error())
		assert.Nil(t, certificate)
	})

	t.Run("unknown CA: certificate missing", func(t *testing.T) {
		// Setup
		client := createCrypto(t)
		client.GenerateKeyPair(ca, false)
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{CommonName: endEntityKey.Owner()},
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, caPrivateKey)
		if !assert.NoError(t, err) {
			return
		}
		// Sign
		certificate, err := client.SignCertificate(endEntityKey, ca, csr, CertificateProfile{})
		// Verify
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), ErrUnknownCA.Error())
		}
		assert.Nil(t, certificate)
	})
}

func TestCrypto_generateVendorEphemeralSigningCertificate(t *testing.T) {
	client := createCrypto(t)
	t.Run("ok", func(t *testing.T) {
		ca, err := client.SelfSignVendorCACertificate("BecauseWeCare B.V.")
		if !assert.NoError(t, err) {
			return
		}
		_ = client.StoreVendorCACertificate(ca)
		certificate, key, err := client.generateVendorEphemeralSigningCertificate()
		t.Run("Key and certificate are returned", func(t *testing.T) {
			assert.Nil(t, err)
			assert.NotNil(t, certificate)
			assert.NotNil(t, key)
		})

		t.Run("verify subject & issuer", func(t *testing.T) {
			assert.Equal(t, "CN=BecauseWeCare B.V. oauth,O=BecauseWeCare B.V.,C=NL", certificate.Subject.String())
			assert.Equal(t, "CN=BecauseWeCare B.V. CA,O=BecauseWeCare B.V.,C=NL", certificate.Issuer.String())
		})
		t.Run("verify VendorID SAN", func(t *testing.T) {
			vendorId, err := cert.VendorIDFromCertificate(certificate)
			assert.NoError(t, err)
			assert.Equal(t, "123", vendorId)
		})
		t.Run("verify Domain extension", func(t *testing.T) {
			domain, err := cert.DomainFromCertificate(certificate)
			assert.NoError(t, err)
			assert.Equal(t, "healthcare", domain)
		})
	})
}

func TestCrypto_generateVendorEphemeralSigningCertificate2(t *testing.T) {
	client := createCrypto(t)
	client.SelfSignVendorCACertificate("test")
	ca := key
	client.GenerateKeyPair(ca, false)

	certificate, err := client.SelfSignVendorCACertificate("test")
	if !assert.NoError(t, err) {
		return
	}
	err = client.StoreVendorCACertificate(certificate)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("does not fail for correct CA", func(t *testing.T) {
		cert, sk, err := client.generateVendorEphemeralSigningCertificate()
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, sk)
		assert.NotNil(t, cert)
	})
}

func TestCryptoConfig_TrustStore(t *testing.T) {
	createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		client := createCrypto(t)
		client.doConfigure()
		assert.NotNil(t, client.TrustStore())
	})
}

func TestCrypto_TrustStore(t *testing.T) {
	createCrypto(t)

	t.Run("ok", func(t *testing.T) {
		client := createCrypto(t)
		client.doConfigure()
		assert.NotNil(t, client.TrustStore())
	})
}

func selfSignCACertificate(client Client, key types.KeyIdentifier) (*x509.Certificate, error) {
	return selfSignCACertificateEx(client, key, pkix.Name{CommonName: key.Owner()}, time.Now(), 365*3)
}

func selfSignCACertificateEx(client Client, key types.KeyIdentifier, name pkix.Name, notBefore time.Time, daysValid int) (*x509.Certificate, error) {
	subjectAltName, _ := cert.MarshalOtherSubjectAltName(cert.OIDNutsVendor, "Foobar")
	csrTemplate := x509.CertificateRequest{
		Subject: name,
		ExtraExtensions: []pkix.Extension{
			extension,
			{Id: cert.OIDSubjectAltName, Critical: false, Value: subjectAltName},
		},
	}
	privateKey, err := client.GetPrivateKey(key)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}
	certBytes, err := client.SignCertificate(key, key, csr, CertificateProfile{
		IsCA:       true,
		MaxPathLen: 1,
		notBefore:  notBefore,
		notAfter:   notBefore.AddDate(0, 0, daysValid),
	})
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

type CertificateRequest x509.CertificateRequest

func (csr CertificateRequest) getUniqueExtension(oid string) (*pkix.Extension, error) {
	extensions := csr.Extensions
	return getUniqueExtension(oid, extensions)
}

func getUniqueExtension(oid string, extensions []pkix.Extension) (*pkix.Extension, error) {
	var result pkix.Extension
	for _, ext := range extensions {
		if ext.Id.String() == oid {
			if result.Id.String() != "" {
				return nil, fmt.Errorf("multiple extensions with OID: %s", oid)
			}
			result = ext
		}
	}
	if result.Id.String() == "" {
		return nil, fmt.Errorf("no extensions with OID: %s", oid)
	}
	return &result, nil
}
