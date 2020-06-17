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
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-crypto/api"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	engine "github.com/nuts-foundation/nuts-go-core"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NewCryptoEngine the engine configuration for nuts-go.
func NewCryptoEngine() *engine.Engine {
	cb := pkg.CryptoInstance()

	return &engine.Engine{
		Cmd:       cmd(),
		Config:    &cb.Config,
		ConfigKey: "crypto",
		Configure: cb.Configure,
		FlagSet:   flagSet(),
		Name:      "Crypto",
		Routes: func(router engine.EchoRouter) {
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
		Use:   "server",
		Short: "Run standalone crypto server",
		Run: func(cmd *cobra.Command, args []string) {
			cryptoEngine := pkg.CryptoInstance()
			echoServer := echo.New()
			echoServer.HideBanner = true
			echoServer.Use(middleware.Logger())
			api.RegisterHandlers(echoServer, &api.ApiWrapper{C: cryptoEngine})
			logrus.Fatal(echoServer.Start(":1324"))
		},
	})

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
			if _, err := cc.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: args[0]})); err != nil {
				cmd.Printf("Error generating keyPair: %v\n", err)
			} else {
				cmd.Println("KeyPair generated")
			}
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "publicKey [legalEntityURI]",
		Short: "views the publicKey for a given legal entity",
		Long:  "views the publicKey for a given legal entity. It'll output a JWK encoded public key and a (deprecated, <= 0.11.0) PEM encoded public key.",

		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("requires a URI argument")
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cc := pkg.NewCryptoClient()
			le := types.LegalEntity{URI: args[0]}

			// printout in JWK
			jwk, err := cc.GetPublicKeyAsJWK(types.KeyForEntity(le))
			if err != nil {
				cmd.Printf("Error printing publicKey: %v", err)
				return
			}
			asJSON, err := json.MarshalIndent(jwk, "", "  ")
			if err != nil {
				cmd.Printf("Error printing publicKey: %v\n", err)
				return
			}
			cmd.Println("Public key in JWK:")
			cmd.Println(string(asJSON))
			cmd.Println("")

			// printout in PEM
			inPem, err := cc.GetPublicKeyAsPEM(types.KeyForEntity(le))
			if err != nil {
				cmd.Printf("Error printing publicKey: %v\n", err)
				return
			}
			cmd.Println("Public key in PEM:")
			cmd.Println(inPem)
		},
	})

	return cmd
}
