package main

import (
	"github.com/nuts-foundation/nuts-crypto/engine"
	"github.com/nuts-foundation/nuts-go-core/docs"
)

func main() {
	docs.GenerateConfigOptionsDocs("README_options.rst", engine.NewCryptoEngine().FlagSet)
}
