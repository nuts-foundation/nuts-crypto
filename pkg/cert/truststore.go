package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-crypto/log"
	errors2 "github.com/pkg/errors"
)

type Verifier interface {
	// Verify verifies the given certificate. The validity of the certificate is checked against the given moment in time.
	Verify(*x509.Certificate, time.Time) error
	// VerifiedChain verifies the certificate against the truststore and returns the chain of trust as result
	// multiple chains can apply but this should only happen when the VendorCA was renewed (overlapping certs)
	VerifiedChain(*x509.Certificate, time.Time) ([][]*x509.Certificate, error)
}

type TrustStore interface {
	Verifier
	AddCertificate(certificate *x509.Certificate) error
	// GetRoots returns all roots active
	Roots() ([]*x509.Certificate, *x509.CertPool)
	// GetIntermediates returns all intermediates
	Intermediates() ([]*x509.Certificate, *x509.CertPool)
	// GetCertificates returns all certificates signed by given signer chains, active at the given time and if it must be a CA
	// The chain is returned in reverse order, the latest in the chain being the root. This is also the order the certificates in the chain
	// param are expected
	GetCertificates([][]*x509.Certificate, time.Time, bool) [][]*x509.Certificate
}

func NewTrustStore(file string) (TrustStore, error) {
	trustStore := &fileTrustStore{
		rootPool:         x509.NewCertPool(),
		intermediatePool: x509.NewCertPool(),
		roots:            make([]*x509.Certificate, 0),
		intermediates:    make([]*x509.Certificate, 0),
		allCerts:         make([]*x509.Certificate, 0),
		mutex:            &sync.Mutex{},
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
	rootPool         *x509.CertPool
	intermediatePool *x509.CertPool
	// x509.CertPool doesn't allow you to extract the certificates in it, so we need to keep our own administration.
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	allCerts      []*x509.Certificate
	file          string
	// mutex secures concurrent access to AddCertificate() since it might be called concurrently, which is bad since
	// it does some file manipulation.
	mutex *sync.Mutex
}

func (m *fileTrustStore) addCertificate(certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("certificate is nil")
	}
	if m.contains(certificate) {
		return nil
	}
	if isSelfSigned(certificate) {
		m.rootPool.AddCert(certificate)
		m.roots = append(m.roots, certificate)
	} else {
		m.intermediatePool.AddCert(certificate)
		m.intermediates = append(m.intermediates, certificate)
	}
	m.allCerts = append(m.allCerts, certificate)

	return nil
}

func (m *fileTrustStore) AddCertificate(certificate *x509.Certificate) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if err := m.addCertificate(certificate); err != nil {
		return err
	}
	return m.save()
}

// GetRoots returns the list of root certificates and a CertPool for convenience
func (m *fileTrustStore) Roots() ([]*x509.Certificate, *x509.CertPool) {
	return m.roots, m.rootPool
}

// GetRoots returns the list of intermediate certificates and a CertPool for convenience
func (m fileTrustStore) Intermediates() ([]*x509.Certificate, *x509.CertPool) {
	return m.intermediates, m.intermediatePool
}

func (m *fileTrustStore) GetCertificates(chain [][]*x509.Certificate, moment time.Time, isCA bool) [][]*x509.Certificate {
	var certs [][]*x509.Certificate
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	rootsAndIntermediates := map[*x509.Certificate]bool{}

	// construct roots with signers and its signers
	for _, subChain := range chain {
		for i, c := range subChain {
			if i == len(subChain)-1 {
				roots.AddCert(c)
			} else {
				intermediates.AddCert(c)
			}
			rootsAndIntermediates[c] = true
		}
	}

	for _, c := range m.allCerts {
		if c.IsCA == isCA && !rootsAndIntermediates[c] {
			chain, err := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: moment})
			if err == nil {
				for _, subChain := range chain {
					certs = append(certs, subChain)
				}
			}
		}
	}

	return certs
}

func isSelfSigned(cert *x509.Certificate) bool {
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.IsCA {
		return cert.CheckSignatureFrom(cert) == nil
	}

	return false
}

func (m *fileTrustStore) contains(certificate *x509.Certificate) bool {
	for _, cert := range m.allCerts {
		if cert.Equal(certificate) {
			return true
		}
	}
	return false
}

func (m *fileTrustStore) save() error {
	buffer := new(bytes.Buffer)
	if err := write(buffer, m.roots); err != nil {
		return err
	}
	if err := write(buffer, m.intermediates); err != nil {
		return err
	}
	stat, _ := os.Stat(m.file)
	return ioutil.WriteFile(m.file, buffer.Bytes(), stat.Mode())
}

func write(buffer *bytes.Buffer, certs []*x509.Certificate) error {
	for _, cert := range certs {
		if err := pem.Encode(buffer, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return err
		}
	}
	return nil
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
		if err = m.addCertificate(certificate); err != nil {
			return errors2.Wrap(err, "unable to add truststore certificate")
		}
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
	// todo pass ExtKeyUsage?
	_, err := cert.Verify(x509.VerifyOptions{Roots: m.rootPool, Intermediates: m.intermediatePool, CurrentTime: moment, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

func (m fileTrustStore) VerifiedChain(cert *x509.Certificate, moment time.Time) ([][]*x509.Certificate, error) {
	// todo pass ExtKeyUsage?
	return cert.Verify(x509.VerifyOptions{Roots: m.rootPool, Intermediates: m.intermediatePool, CurrentTime: moment, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
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
