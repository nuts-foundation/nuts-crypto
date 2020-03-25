package algo

import "testing"

func TestRSAKeyFamily(t *testing.T) {
	family := getRSAKeyFamily()
	for _, kt := range family.supportedKT {
		testKeyType(t, kt, family)
	}
}
