package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/nuts-foundation/nuts-crypto/log"
	errors2 "github.com/pkg/errors"
	"io/ioutil"
	"os"
	"sync"
	"time"
)

type Verifier interface {
	// Verify verifies the given certificate. The validity of the certificate is checked against the given moment in time.
	Verify(*x509.Certificate, time.Time) error
}

type TrustStore interface {
	Verifier
	Pool() *x509.CertPool
	AddCertificate(certificate *x509.Certificate) error
}

func NewTrustStore(file string) (TrustStore, error) {
	trustStore := &fileTrustStore{
		pool:  x509.NewCertPool(),
		certs: make([]*x509.Certificate, 0),
		mutex: &sync.Mutex{},
	}
	if exists, err := exists(file); err != nil {
		return nil, errors2.Wrap(err, "error checking for existing truststore")
	} else if !exists {
		log.Logger().Warnf("Truststore does not exist, creating (but it will be empty): %s", file)
		if err := ioutil.WriteFile(file, []byte{}, 0600); err != nil {
			return nil, errors2.Wrap(err, "unable to create new truststore")
		}
	}
	if err := trustStore.load(file); err != nil {
		return nil, err
	}
	return trustStore, nil
}

type fileTrustStore struct {
	pool *x509.CertPool
	// x509.CertPool doesn't allow you to extract the certificates in it, so we need to keep our own administration.
	certs []*x509.Certificate
	file  string
	// mutex secures concurrent access to AddCertificate() since it might be called concurrently, which is bad since
	// it does some file manipulation.
	mutex *sync.Mutex
}

func (m fileTrustStore) Pool() *x509.CertPool {
	return m.pool
}

func (m *fileTrustStore) AddCertificate(certificate *x509.Certificate) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if certificate == nil {
		return errors.New("certificate is nil")
	}
	if m.contains(certificate) {
		return nil
	}
	m.pool.AddCert(certificate)
	m.certs = append(m.certs, certificate)
	return m.save()
}

func (m *fileTrustStore) contains(certificate *x509.Certificate) bool {
	for _, cert := range m.certs {
		if cert.Equal(certificate) {
			return true
		}
	}
	return false
}

func (m *fileTrustStore) save() error {
	buffer := new(bytes.Buffer)
	for _, cert := range m.certs {
		if err := pem.Encode(buffer, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return err
		}
	}
	stat, _ := os.Stat(m.file)
	return ioutil.WriteFile(m.file, buffer.Bytes(), stat.Mode())
}

func (m *fileTrustStore) load(file string) error {
	m.file = file
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return errors2.Wrapf(err, "unable to read truststore file: %s", file)
	}
	// The code below is also (more or less) found in x509.CertPool but need to keep our own list of certificates
	// since we want to be able to save when a certificate is added.
	blocks, err := findBlocksInPEM(data, "CERTIFICATE")
	if err != nil {
		return errors2.Wrapf(err, "unable to load truststore from file: %s", file)
	}
	if len(blocks) == 0 {
		log.Logger().Warnf("No certificates found in truststore: %s", file)
	}
	for _, block := range blocks {
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors2.Wrap(err, "unable to parse truststore certificate")
		}
		m.certs = append(m.certs, certificate)
		m.pool.AddCert(certificate)
	}
	return nil
}

func exists(file string) (bool, error) {
	info, err := os.Stat(file)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

func (m fileTrustStore) Verify(cert *x509.Certificate, moment time.Time) error {
	_, err := cert.Verify(x509.VerifyOptions{Roots: m.pool, CurrentTime: moment})
	return err
}

func findBlocksInPEM(data []byte, blockType string) ([]*pem.Block, error) {
	blocks := make([]*pem.Block, 0)
	if len(data) == 0 {
		return blocks, nil
	}
	var rest = data
	for {
		block, r := pem.Decode(rest)
		if len(r) == len(rest) {
			return nil, errors.New("data is not in PEM format")
		}
		if block == nil {
			break
		}
		if block.Type == blockType {
			blocks = append(blocks, block)
		}
		if len(r) == 0 {
			break
		}
		rest = r
	}
	return blocks, nil
}