package algo

import "fmt"

type KeyFamily interface {
	Name() string
	IsKeySupported(key interface{}) bool
	RecommendedKeyTypes() []KeyType
	SupportedKeyTypes() []KeyType
	RecommendedSigningAlgorithms() []SigningAlgorithm
	SupportedSigningAlgorithms() []SigningAlgorithm
}

type KeyType interface {
	Identifier() string
	Generate() (privKey interface{}, pubKey interface{}, err error)
	Matches(key interface{}) bool
	MarshalPEM(key interface{}) (string, error)
}

type SigningAlgorithm interface {
	JWAIdentifier() string
}

func UnsupportedKeyTypeError(kt interface{}) error {
	str, ok := kt.(string)
	if !ok {
		str = fmt.Sprintf("%T", kt)
	}
	return fmt.Errorf("unsupported key type: %s", str)
}
