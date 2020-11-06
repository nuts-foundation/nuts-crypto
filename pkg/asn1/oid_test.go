package asn1

import (
	"encoding/asn1"
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestOIDAppend(t *testing.T) {
	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 3, 4}, OIDAppend(asn1.ObjectIdentifier{1, 2, 3}, 4))
}
