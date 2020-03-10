package asn1

import "encoding/asn1"

func OIDAppend(base asn1.ObjectIdentifier, v int) asn1.ObjectIdentifier {
	r := make([]int, len(base), len(base)+1)
	copy(r, base)
	return append(r, v)
}
