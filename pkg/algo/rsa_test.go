package algo

import "testing"

func TestRSACipherSuite(t *testing.T) {
	for _, kt := range getRSAKeyTypes() {
		testKeyType(t, kt)
	}
}
