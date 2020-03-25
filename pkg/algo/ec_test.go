package algo

import (
	"testing"
)

func TestECKeyFamily(t *testing.T) {
	family := getECKeyFamily()
	for _, kt := range family.supportedKT {
		testKeyType(t, kt, family)
	}
}
