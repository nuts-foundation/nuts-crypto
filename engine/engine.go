/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package engine

import (
	"errors"
	"fmt"
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/nuts-foundation/nuts-crypto/api"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	engine "github.com/nuts-foundation/nuts-go/pkg"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NewCryptoEngine the engine configuration for nuts-go.
func NewCryptoEngine() *engine.Engine {
	cb := pkg.CryptoInstance()

	return &engine.Engine {
		Cmd:       cmd(),
		Config:	   &cb.Config,
		ConfigKey: "crypto",
		Configure: cb.Configure,
		FlagSet:   flagSet(),
		Name:      "Crypto",
		Routes: func(router runtime.EchoRouter) {
			api.RegisterHandlers(router, &api.ApiWrapper{C: cb})
		},
	}
}

// FlagSet returns the configuration possibilities for crypto: --backend, --fspath, --keysize
func flagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	flags.String(types.ConfigStorage, types.ConfigStorageFs, "storage to use, 'fs' for file system (default)")
	flags.String(types.ConfigFSPath, types.ConfigFSPathDefault, "when file system is used as storage, this configures the path where keys are stored (default .)")
	flags.Int(types.ConfigKeySize, types.ConfigKeySizeDefault, "number of bits to use when creating new RSA keys")

	return flags
}

// Cmd gives the sub-commands made available through crypto:
// * generateKeyPair: generate a new keyPair for a given legalEntity
// * publicKey: retrieve the keyPair for a given legalEntity
func cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "crypto commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "generateKeyPair [legalEntityURI]",
		Short: "generate a new keyPair for a legalEntity",

		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("requires a URI argument")
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cc := pkg.NewCryptoClient()
			if err := cc.GenerateKeyPairFor(types.LegalEntity{URI: args[0]}); err != nil {
				fmt.Printf("Error generating keyPair: %v\n", err)
			} else {
				fmt.Println("KeyPair generated")
			}
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "publicKey [legalEntityURI]",
		Short: "views the publicKey for a given legal entity",

		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("requires a URI argument")
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cc := pkg.NewCryptoClient()
			bytes, err := cc.PublicKey(types.LegalEntity{URI: args[0]})

			if err != nil {
				fmt.Printf("Error printing publicKey: %v", err)
			}

			fmt.Println(string(bytes))
		},
	})

	return cmd
}
