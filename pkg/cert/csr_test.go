package cert

import (
	"testing"

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
