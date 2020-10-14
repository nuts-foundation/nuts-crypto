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
	"crypto"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-crypto/api"
	"github.com/nuts-foundation/nuts-crypto/client"
	"github.com/nuts-foundation/nuts-crypto/log"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
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
		Start:    cb.Start,
		Shutdown: cb.Shutdown,
	}
}

// FlagSet returns the configuration flags for crypto
func flagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	defs := pkg.DefaultCryptoConfig()
	flags.String(types.ConfigMode, defs.Mode, fmt.Sprintf("Server or client, when client it uses the HttpClient, default: %s", defs.Mode))
	flags.String(types.ConfigAddress, defs.Address, fmt.Sprintf("Interface and port for http server to bind to, default: %s", defs.Address))
	flags.Int(types.ConfigClientTimeout, defs.ClientTimeout, fmt.Sprintf("Time-out for the client in seconds (e.g. when using the CLI), default: %d", defs.ClientTimeout))
	flags.String(types.ConfigStorage, defs.Storage, fmt.Sprintf("Storage to use, 'fs' for file system, default: %s", defs.Storage))
	flags.String(types.ConfigFSPath, defs.Fspath, fmt.Sprintf("When file system is used as storage, this configures the path where key material and the truststore are persisted, default: %v", defs.Fspath))
	flags.Int(types.ConfigKeySize, defs.Keysize, fmt.Sprintf("Number of bits to use when creating new RSA keys, default: %d", defs.Keysize))

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

	{
		var overwrite *bool
		generateKeyPairCmd := cobra.Command{
			Use:   "generateKeyPair [legalEntityURI]",
			Short: "generate a new keyPair for a legalEntity",
			Args: func(cmd *cobra.Command, args []string) error {
				if len(args) < 1 {
					return errors.New("requires a URI argument")
				}

				return nil
			},
			Run: func(cmd *cobra.Command, args []string) {
				cc := client.NewCryptoClient()
				if _, err := cc.GenerateKeyPair(types.KeyForEntity(types.LegalEntity{URI: args[0]}), *overwrite); err != nil {
					cmd.Printf("Error generating keyPair: %v\n", err)
				} else {
					cmd.Println("KeyPair generated")
				}
			},
		}
		flagSet := pflag.NewFlagSet(generateKeyPairCmd.Name(), pflag.ContinueOnError)
		overwrite = flagSet.BoolP("force", "f", false, "overwrite if the given key already exists")
		generateKeyPairCmd.Flags().AddFlagSet(flagSet)
		cmd.AddCommand(&generateKeyPairCmd)
	}

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
			cc := client.NewCryptoClient()
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
			var publicKey interface{}
			if err := jwk.Raw(&publicKey); err != nil {
				cmd.Printf("Error printing publicKey: %v\n", err)
				return
			} else {
				publicKeyAsPEM, err := cert.PublicKeyToPem(publicKey.(crypto.PublicKey))
				if err != nil {
					cmd.Printf("Error printing publicKey: %v\n", err)
					return
				}
				cmd.Println("Public key in PEM:")
				cmd.Println(publicKeyAsPEM)
			}
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "generate-vendor-csr [name] [OPTIONAL output-file]",
		Short: "Generates a CSR for the current vendor with the given name.",
		Long:  "Generates a CSR for the current vendor with the given name. If output-file is specified, the resulting PKCS#10 is written to that location in PEM format.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Logger().Infof("Generating Vendor CA CSR for '%s'", args[0])
			cc := client.NewCryptoClient()
			csr, err := cc.GenerateVendorCACSR(args[0])
			if err != nil {
				log.Logger().Errorf("Error while generating CSR: %v", err)
				return err
			}
			csrAsPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: csr,
			})
			if len(args) == 1 {
				cmd.Println(string(csrAsPEM))
			} else {
				outputFile := args[1]
				cmd.Println(fmt.Sprintf("Writing CSR to %s", outputFile))
				return ioutil.WriteFile(outputFile, csrAsPEM, 0777)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "selfsign-vendor-cert [name] [OPTIONAL output-file]",
		Short: "Self-signs a X.509 certificate for the current vendor with the given name.",
		Long: "Self-signs a X.509 certificate for the current vendor with the given name. " +
			"This is the self-signed variant of the 'generate-vendor-csr' command. " +
			"If there is an existing key pair for the vendor that one is reused, otherwise a new key pair is generated. " +
			"The certificate is printed in PEM encoded form.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Logger().Infof("Self-signing Vendor CA certificate for '%s'", args[0])
			cc := client.NewCryptoClient()
			certificate, err := cc.SelfSignVendorCACertificate(args[0])
			if err != nil {
				log.Logger().Errorf("Error while self-signing : %v", err)
				return err
			}
			certificateAsPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certificate.Raw,
			})
			if len(args) == 1 {
				cmd.Println(string(certificateAsPEM))
			} else {
				outputFile := args[1]
				cmd.Println(fmt.Sprintf("Writing certificate to %s", outputFile))
				return ioutil.WriteFile(outputFile, certificateAsPEM, 0777)
			}
			return nil
		},
	})

	return cmd
}
