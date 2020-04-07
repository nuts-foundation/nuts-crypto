package algo

import (
	"testing"
)

func TestECKeyFamily(t *testing.T) {
	for _, kt := range getECKeyTypes() {
		testKeyType(t, kt)
	}
}
