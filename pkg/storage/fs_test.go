package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-crypto/test"
	"github.com/stretchr/testify/assert"
)

const testCert = `
-----BEGIN CERTIFICATE-----
MIICvDCCAaSgAwIBAgIIFQhlqiLrrbgwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE
AxMHUm9vdCBDQTAeFw0yMDAyMTMxMjQzNTdaFw0yMDAyMTQxMjQzNTdaMBIxEDAO
BgNVBAMTB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA
0uYU5crtuXcq1zSR67JVDU4a9Eg4si1IqrZf1fyKlEBHG0OPi+P246a0iz0Kpbvp
Rz+mrAAtrUbZXpeKYByeVMCzRwaqNWpUequaXnGoGRjMS734lZHP1NQaq60kS7MR
ts9rzkNK6U7WXKwzq1l1IaI1lhxNEZy1siB1lvYeNN6Q5yrVmxfhZgygJZB7LDmg
L1xtk5HmcakZD7G5sAnxT5ocm5+b/nQT4H6vOaiGk+Y89+5c/UMjotly6U1+pwMj
hMqCrd1WJGrz7MVN+d11s+4kiBoZmch3hnY1bqxwlKS+lWq+0k4/SlLpB9G23ril
6FHd2h59MUrVYywAnHmpAgMBAAGjFjAUMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJ
KoZIhvcNAQELBQADggEBAJ3/eolsKVLZVLOnSpahH9/Je88qs3k9X8tQ5TECq2ZO
E8EbilhlENKXE5RuaMNK4I+6vOh8qw/1L1W9/6IBUtn2IDgxBHzNHwCElK2sRS9Q
8tA3WDNmDRnLCKGJ91N2i/GOu6UVPjemJVpAmDhTw3ypyLLFyirxGHy8pgoz2wZP
QVQWt0SE3h24xnQYFBA4sAas3ifYYAKr4kUEg9RETz/ePqFkZuX7ee3j/RQafAK8
2SmawIR85H7qeB4BpZyfT8ah8tsnC7l+V3cmRIwxjukQu5c2x2xmcTFr2qi0tta6
sA7xv2k51lnp+CmY20vz5FMXWlktmgQN3J9uKIMlBQ4=
-----END CERTIFICATE-----
`

var key = types.KeyForEntity(types.LegalEntity{URI: "Some Entity"})

func Test_fs_SaveThenLoadCertificate(t *testing.T) {
	storage := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	t.Run("save certificate", func(t *testing.T) {
		block, rest := pem.Decode([]byte(testCert))
		if !assert.Len(t, rest, 0, "unable to decode cert") {
			return
		}
		err := storage.SaveCertificate(key, block.Bytes)
		assert.NoError(t, err)
	})
	t.Run("load certificate", func(t *testing.T) {
		certificate, err := storage.GetCertificate(key)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "CN=Root CA", certificate.Subject.String())
	})
}

func Test_fs_GetCertificate(t *testing.T) {
	storage := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	t.Run("entry does not exist", func(t *testing.T) {
		certificate, err := storage.GetCertificate(types.KeyForEntity(types.LegalEntity{URI: "abc"}))
		assert.Nil(t, certificate)
		assert.Error(t, err)
	})
	t.Run("incorrect certificate", func(t *testing.T) {
		storage.SaveCertificate(key, []byte{1, 2, 3})
		certificate, err := storage.GetCertificate(key)
		assert.Nil(t, certificate)
		assert.Error(t, err)
	})
	t.Run("trailing bytes", func(t *testing.T) {
		block, _ := pem.Decode([]byte(testCert))
		err := storage.SaveCertificate(key, block.Bytes)
		if !assert.NoError(t, err) {
			return
		}
		path := storage.getEntryPath(key, certificateEntry)
		file, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		_, err = file.WriteString("some trailing bytes")
		if !assert.NoError(t, err) {
			return
		}
		certificate, err := storage.GetCertificate(key)
		assert.Nil(t, certificate)
		assert.Error(t, err)
	})
}

func Test_fs_GetPublicKey(t *testing.T) {
	storage := createTempStorage(t.Name())
	defer emptyTemp(t.Name())
	t.Run("non-existing entry", func(t *testing.T) {
		key, err := storage.GetPublicKey(key)
		assert.EqualError(t, err, "could not open entry [Some Entity|] with filename temp/Test_fs_GetPublicKey/U29tZSBFbnRpdHk=_private.pem: entry not found", "error")
		assert.Nil(t, key)
	})
	t.Run("ok", func(t *testing.T) {
		pk, _ := rsa.GenerateKey(rand.Reader, 2048)
		err := storage.SavePrivateKey(key, pk)
		if !assert.NoError(t, err) {
			return
		}
		key, err := storage.GetPublicKey(key)
		assert.NoError(t, err)
		if !assert.NotNil(t, key) {
			return
		}
		assert.Equal(t, &pk.PublicKey, key)
	})
}

func Test_fs_GetPrivateKey(t *testing.T) {
	storage := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	t.Run("non-existing entry", func(t *testing.T) {
		key, err := storage.GetPrivateKey(key)
		assert.EqualError(t, err, "could not open entry [Some Entity|] with filename temp/Test_fs_GetPrivateKey/U29tZSBFbnRpdHk=_private.pem: entry not found", "error")
		assert.Nil(t, key)
	})
	t.Run("private key invalid", func(t *testing.T) {
		path := storage.getEntryPath(key, privateKeyEntry)
		file, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
		_, err := file.WriteString("hello world")
		if !assert.NoError(t, err) {
			return
		}
		key, err := storage.GetPrivateKey(key)
		assert.Nil(t, key)
		assert.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		pk, _ := rsa.GenerateKey(rand.Reader, 2048)
		err := storage.SavePrivateKey(key, pk)
		if !assert.NoError(t, err) {
			return
		}
		key, err := storage.GetPrivateKey(key)
		assert.NoError(t, err)
		if !assert.NotNil(t, key) {
			return
		}
		assert.Equal(t, pk, key)
	})
}

func Test_fs_KeyExistsFor(t *testing.T) {
	storage := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	t.Run("non-existing entry", func(t *testing.T) {
		assert.False(t, storage.PrivateKeyExists(key))
	})
	t.Run("existing entry", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		storage.SavePrivateKey(key, privateKey)
		assert.True(t, storage.PrivateKeyExists(key))
	})
}

func Test_fs_CertificateExistsFor(t *testing.T) {
	storage := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	t.Run("ok - non-existing entry", func(t *testing.T) {
		assert.False(t, storage.CertificateExists(key))
	})
	t.Run("ok - non-existing entry with qualifier", func(t *testing.T) {
		assert.False(t, storage.CertificateExists(key.WithQualifier("foo")))
	})
	t.Run("ok - non-existing entry with qualifier (2)", func(t *testing.T) {
		storage.SaveCertificate(key, []byte{1, 2, 3})
		assert.False(t, storage.CertificateExists(key.WithQualifier("foo")))
	})
	t.Run("ok - existing entry", func(t *testing.T) {
		storage.SaveCertificate(key, []byte{1, 2, 3})
		assert.True(t, storage.CertificateExists(key))
	})
	t.Run("ok - existing entry with qualifier", func(t *testing.T) {
		storage.SaveCertificate(key.WithQualifier("foo"), []byte{1, 2, 3})
		assert.True(t, storage.CertificateExists(key))
	})
}

func Test_fs_GetExpiringCertificates(t *testing.T) {
	storage := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	// expires in 8 days
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	storage.SaveCertificate(key, test.GenerateCertificate(time.Now().AddDate(0, 0, -1), 9, rsaKey))

	t.Run("Expiring certificate is found within correct period", func(t *testing.T) {
		certs, err := storage.GetExpiringCertificates(time.Now(), time.Now().AddDate(0, 0, 14))
		if assert.NoError(t, err) {
			assert.Len(t, certs, 1)
		}
	})

	t.Run("Expiring certificate is not found outside period", func(t *testing.T) {
		certs, err := storage.GetExpiringCertificates(time.Now(), time.Now().AddDate(0, 0, 7))
		if assert.NoError(t, err) {
			assert.Len(t, certs, 0)
		}
	})

	t.Run("returns error when certificate with incorrect format is on the path", func(t *testing.T) {
		storage := createTempStorage(t.Name())
		defer emptyTemp(t.Name())

		fileName := fmt.Sprintf("temp/%s/incorrect_%s", t.Name(), certificateEntry)
		_ = os.MkdirAll(fmt.Sprintf("temp/%s", t.Name()), 0644)
		_ = ioutil.WriteFile(fileName, []byte("this will return an error, this is not PEM encoded"), 0644)

		_, err := storage.GetExpiringCertificates(time.Now(), time.Now())
		assert.Error(t, err)
	})
}

func createTempStorage(name string) *fileSystemBackend {
	b, _ := NewFileSystemBackend(fmt.Sprintf("temp/%s", name))
	return b
}

func emptyTemp(name string) {
	err := os.RemoveAll(fmt.Sprintf("temp/%s", name))
	if err != nil {
		println(err.Error())
	}
	err = os.Remove("temp")
	if err != nil {
		println(err.Error())
	}
}
