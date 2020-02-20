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
	"bytes"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-go-core/mock"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestNewCryptoEngine(t *testing.T) {
	t.Run("New returns an engine with Cmd and Routes", func(t *testing.T) {
		client := NewCryptoEngine()

		if client.Cmd == nil {
			t.Errorf("Expected Engine to have Cmd")
		}

		if client.Routes == nil {
			t.Errorf("Expected Engine to have Routes")
		}
	})
}

func TestNewCryptoEngine_Routes(t *testing.T) {
	t.Run("Registers the 4 available routes", func(t *testing.T) {
		ce := NewCryptoEngine()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockEchoRouter(ctrl)

		echo.EXPECT().POST("/crypto/sign", gomock.Any())
		echo.EXPECT().POST("/crypto/verify", gomock.Any())
		echo.EXPECT().POST("/crypto/decrypt", gomock.Any())
		echo.EXPECT().POST("/crypto/encrypt", gomock.Any())
		echo.EXPECT().POST("/crypto/external_id", gomock.Any())
		echo.EXPECT().POST("/crypto/generate", gomock.Any())
		echo.EXPECT().POST("/crypto/sign_jwt", gomock.Any())
		echo.EXPECT().GET("/crypto/public_key/:urn", gomock.Any())

		ce.Routes(echo)
	})
}

func TestNewCryptoEngine_Cmd(t *testing.T) {
	defer emptyTemp()

	e := NewCryptoEngine()
	c := pkg.CryptoInstance()
	c.Config.Fspath = "../temp"
	c.Configure()
	c.GenerateKeyPairFor(types.LegalEntity{URI: "legalEntity"})
	cmd := e.Cmd

	t.Run("Cmd returns a command with a single subCommand", func(t *testing.T) {
		assert.Equal(t, "crypto", cmd.Name())
		assert.Len(t, cmd.Commands(), 3)
	})

	t.Run("Running generateKeyPair with too few arguments gives error", func(t *testing.T) {
		cmd.SetArgs([]string{"generateKeyPair"})
		cmd.SetOut(ioutil.Discard)
		err := cmd.Execute()

		if assert.Error(t, err) {
			assert.Equal(t, "requires a URI argument", err.Error())
		}
	})

	t.Run("Running generateKeyPair returns 'keypair generated'", func(t *testing.T) {
		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"generateKeyPair", "legalEntity"})
		cmd.SetOut(buf)
		err := cmd.Execute()

		if assert.NoError(t, err) {
			assert.Equal(t, "KeyPair generated\n", buf.String())
		}
	})

	t.Run("Running publicKey with too few arguments gives error", func(t *testing.T) {
		cmd.SetArgs([]string{"publicKey"})
		cmd.SetOut(ioutil.Discard)
		err := cmd.Execute()

		if assert.Error(t, err) {
			assert.Equal(t, "requires a URI argument", err.Error())
		}
	})

	t.Run("Running publicKey returns error if public key does not exist", func(t *testing.T) {
		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"publicKey", "legalEntityMissing"})
		cmd.SetOut(buf)
		err := cmd.Execute()

		if assert.NoError(t, err) {
			expected := "Error printing publicKey: could not open entry for legalEntity: legalEntityMissing with filename ../temp/bGVnYWxFbnRpdHlNaXNzaW5n_private.pem: entry not found"
			assert.Contains(t, buf.String(), expected)
		}
	})

	t.Run("Running publicKey returns pem", func(t *testing.T) {
		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"publicKey", "legalEntity"})
		cmd.SetOut(buf)
		err := cmd.Execute()

		if assert.NoError(t, err) {
			assert.Contains(t, buf.String(), "Public key in PEM:")
			assert.Contains(t, buf.String(), "-----BEGIN PUBLIC KEY-----")
		}
	})

	t.Run("Running publicKey returns JWK", func(t *testing.T) {
		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"publicKey", "legalEntity"})
		cmd.SetOut(buf)
		err := cmd.Execute()

		if assert.NoError(t, err) {
			assert.Contains(t, buf.String(), "Public key in JWK:")
			assert.Contains(t, buf.String(), "kty")
		}
	})
}

func TestNewCryptoEngine_FlagSet(t *testing.T) {
	t.Run("Cobra help should list flags", func(t *testing.T) {
		e := NewCryptoEngine()
		cmd := newRootCommand()
		cmd.Flags().AddFlagSet(e.FlagSet)
		cmd.SetArgs([]string{"--help"})

		buf := new(bytes.Buffer)
		cmd.SetOut(buf)

		_, err := cmd.ExecuteC()

		if err != nil {
			t.Errorf("Expected no error, got %s", err.Error())
		}

		result := buf.String()

		if !strings.Contains(result, "--storage") {
			t.Errorf("Expected --storage to be command line flag")
		}

		if !strings.Contains(result, "--fspath") {
			t.Errorf("Expected --fspath to be command line flag")
		}

	})
}

func newRootCommand() *cobra.Command {
	testRootCommand := &cobra.Command{
		Use: "root",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}

	return testRootCommand
}

func emptyTemp() {
	err := os.RemoveAll("../temp/")

	if err != nil {
		println(err.Error())
	}
}
