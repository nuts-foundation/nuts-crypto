package test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func GenerateCertificateEx(notBefore time.Time, privKey crypto.Signer, validityInDays int, isCA bool, keyUsage x509.KeyUsage) []byte {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Unit Test",
		},
		PublicKey:             privKey.Public(),
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, validityInDays),
		IsCA:                  isCA,
		KeyUsage:              keyUsage,
		EmailAddresses:        []string{"test@test.nl"},
		BasicConstraintsValid: true,
	}
	data, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		panic(err)
	}
	return data
}

func GenerateCertificate(notBefore time.Time, validityInDays int, privKey crypto.Signer) []byte {
	return GenerateCertificateEx(notBefore, privKey, validityInDays, false, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature)
}
