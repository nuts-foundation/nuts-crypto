package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNewTrustStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		trustStore, err := NewTrustStore("../../test/truststore.pem")
		if !assert.NoError(t, err) {
			return
		}
		ts := trustStore.(*fileTrustStore)
		assert.Len(t, ts.certs, 1)
	})
	t.Run("ok - create empty", func(t *testing.T) {
		const file = "non-existent.pem"
		os.Remove(file)
		defer os.Remove(file)
		trustStore, err := NewTrustStore(file)
		if !assert.NoError(t, err) {
			return
		}
		ts := trustStore.(*fileTrustStore)
		assert.Len(t, ts.certs, 0)
	})
	t.Run("ok - mixed", func(t *testing.T) {
		// Loads a mixed PEM file which does contain certificates but also other PEM-encoded objects
		trustStore, err := NewTrustStore("../../test/certificate-and-key.pem")
		if !assert.NoError(t, err) {
			return
		}
		ts := trustStore.(*fileTrustStore)
		assert.Len(t, ts.certs, 1)
	})
	t.Run("ok - roundtrip", func(t *testing.T) {
		const file = "roundtrip.pem"
		os.Remove(file)
		defer os.Remove(file)
		trustStore, err := NewTrustStore(file)
		if !assert.NoError(t, err) {
			return
		}
		ts := trustStore.(*fileTrustStore)
		assert.Len(t, ts.certs, 0)
		err = trustStore.AddCertificate(generateCertificate("Test", time.Now(), 1, generateKeyPair()))
		if !assert.NoError(t, err) {
			return
		}
		trustStore, err = NewTrustStore(file)
		if !assert.NoError(t, err) {
			return
		}
		ts = trustStore.(*fileTrustStore)
		assert.Len(t, ts.certs, 1)
	})
	t.Run("error - path does not exist", func(t *testing.T) {
		trustStore, err := NewTrustStore("/non/existent/path/1234/truststore.pem")
		assert.Nil(t, trustStore)
		assert.EqualError(t, err, "unable to create new truststore: open /non/existent/path/1234/truststore.pem: no such file or directory")
	})
	t.Run("error - file is not a PEM file", func(t *testing.T) {
		trustStore, err := NewTrustStore("truststore_test.go")
		assert.Nil(t, trustStore)
		assert.EqualError(t, err, "unable to load truststore from file: truststore_test.go: data is not in PEM format")
	})
	t.Run("error - invalid cert in PEM file", func(t *testing.T) {
		trustStore, err := NewTrustStore("../../test/truststore-invalid.pem")
		assert.Nil(t, trustStore)
		assert.EqualError(t, err, "unable to parse truststore certificate: asn1: structure error: tags don't match (16 vs {class:0 tag:2 length:1 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} tbsCertificate @2")
	})
}

func Test_fileTrustStore_AddCertificate(t *testing.T) {
	const file = "../../test/addcert.pem"
	privateKey := generateKeyPair()
	t.Run("ok", func(t *testing.T) {
		os.Remove(file)
		defer os.Remove(file)
		trustStore, err := NewTrustStore(file)
		if !assert.NoError(t, err) {
			return
		}
		ts := trustStore.(*fileTrustStore)
		err = trustStore.AddCertificate(generateCertificate(t.Name(), time.Now(), 1, privateKey))
		assert.NoError(t, err)
		assert.Len(t, ts.certs, 1)
		err = trustStore.AddCertificate(generateCertificate(t.Name(), time.Now(), 1, privateKey))
		assert.NoError(t, err)
		assert.Len(t, ts.certs, 2)
	})
	t.Run("ok - duplicate", func(t *testing.T) {
		os.Remove(file)
		defer os.Remove(file)
		trustStore, err := NewTrustStore(file)
		if !assert.NoError(t, err) {
			return
		}
		ts := trustStore.(*fileTrustStore)
		certificate := generateCertificate(t.Name(), time.Now(), 1, privateKey)
		err = trustStore.AddCertificate(certificate)
		assert.NoError(t, err)
		err = trustStore.AddCertificate(certificate)
		assert.NoError(t, err)
		assert.Len(t, ts.certs, 1)
	})
	t.Run("ok - concurrency", func(t *testing.T) {
		os.Remove(file)
		defer os.Remove(file)
		trustStore, err := NewTrustStore(file)
		if !assert.NoError(t, err) {
			return
		}
		var i = 0
		wg := sync.WaitGroup{}
		wg.Add(100)
		for i = 0; i < 100; i++ {
			go func() {
				err := trustStore.AddCertificate(generateCertificate(t.Name(), time.Now(), 1, privateKey))
				assert.NoError(t, err)
				wg.Done()
			}()
		}
		wg.Wait()
		ts := trustStore.(*fileTrustStore)
		assert.Len(t, ts.certs, 100)
	})
	t.Run("error - cert is nil", func(t *testing.T) {
		os.Remove(file)
		defer os.Remove(file)
		trustStore, _ := NewTrustStore(file)
		err := trustStore.AddCertificate(nil)
		assert.EqualError(t, err, "certificate is nil")
	})
}

func Test_fileTrustStore_Pool(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		const file = "pool.pem"
		os.Remove(file)
		defer os.Remove(file)
		trustStore, _ := NewTrustStore(file)
		assert.NotNil(t, trustStore.Pool())
	})
}

func Test_fileTrustStore_Verify(t *testing.T) {
	t.Run("ok - valid", func(t *testing.T) {
		trustStore, _ := NewTrustStore("../../test/truststore.pem")
		err := trustStore.Verify((trustStore.(*fileTrustStore)).certs[0], time.Now())
		assert.NoError(t, err)
	})
	t.Run("ok - not valid", func(t *testing.T) {
		trustStore, _ := NewTrustStore("../../test/truststore.pem")
		err := trustStore.Verify((trustStore.(*fileTrustStore)).certs[0], time.Unix(2000, 0))
		assert.Error(t, err)
	})
}

func Test_fileTrustStore_contains(t *testing.T) {
	type fields struct {
		pool  *x509.CertPool
		certs []*x509.Certificate
		file  string
		mutex *sync.Mutex
	}
	type args struct {
		certificate *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &fileTrustStore{
				pool:  tt.fields.pool,
				certs: tt.fields.certs,
				file:  tt.fields.file,
				mutex: tt.fields.mutex,
			}
			if got := m.contains(tt.args.certificate); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_fileTrustStore_load(t *testing.T) {
	t.Run("error - file does not exist", func(t *testing.T) {
		err := (&fileTrustStore{}).load("non-existent")
		assert.EqualError(t, err, "unable to read truststore file: non-existent: open non-existent: no such file or directory")
	})
}

func generateKeyPair() *rsa.PrivateKey {
	keyPair, _ := rsa.GenerateKey(rand.Reader, 2048)
	return keyPair
}

func generateCertificate(commonName string, notBefore time.Time, validityInDays int, privKey *rsa.PrivateKey) *x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		PublicKey:   privKey.PublicKey,
		NotBefore:   notBefore,
		NotAfter:    notBefore.AddDate(0, 0, validityInDays),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	data, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		panic(err)
	}
	certificate, _ := x509.ParseCertificate(data)
	return certificate
}
