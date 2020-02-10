package storage

import (
	"encoding/pem"
	"fmt"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const cert = `
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

func Test_fs_SaveThenLoadCertificate(t *testing.T) {
	entity := types.LegalEntity{URI: "Some Entity"}
	storage := createTempStorage(t.Name())
	defer emptyTemp(t.Name())

	t.Run("save certificate", func(t *testing.T) {
		block, rest := pem.Decode([]byte(cert))
		if !assert.Len(t, rest, 0, "unable to decode cert") {
			return
		}
		err := storage.SaveCertificate(entity, block.Bytes)
		assert.NoError(t, err)
	})
	t.Run("load certificate", func(t *testing.T) {
		certificate, err := storage.GetCertificate(entity)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "CN=Root CA", certificate.Subject.String())
	})
}

func createTempStorage(name string) Storage {
	b, _ := NewFileSystemBackend(fmt.Sprintf("temp/%s", name))
	return b
}

func emptyTemp(name string) {
	err := os.RemoveAll(fmt.Sprintf("temp/%s", name))
	if err != nil {
		println(err.Error())
	}
}
