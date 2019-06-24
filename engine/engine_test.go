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
	"github.com/nuts-foundation/nuts-go/mock"
	"github.com/spf13/cobra"
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

		ce.Routes(echo)
	})
}

func TestNewCryptoEngine_Cmd(t *testing.T) {
	defer emptyTemp()

	e := NewCryptoEngine()
	c := pkg.CryptoInstance()
	c.Config.Fspath = "../temp"
	c.Configure()

	t.Run("Cmd returns a command with a single subCommand", func(t *testing.T) {
		cmd := e.Cmd
		if cmd.Name() != "crypto" {
			t.Errorf("Expected Cmd name to equal [crypto], got %s", cmd.Name())
		}

		if len(cmd.Commands()) != 2 {
			t.Errorf("Expected Cmd to have 1 sub-command, got %d", len(cmd.Commands()))
		}
	})

	t.Run("Running generateKeyPair with too few arguments gives error", func(t *testing.T) {
		cmd := e.Cmd

		cmd.SetArgs([]string{"generateKeyPair"})
		cmd.SetOutput(new(bytes.Buffer))
		err := cmd.Execute()

		if err == nil {
			t.Error("Expected error, got nothing")
		}

		expected := "requires a URI argument"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})

	t.Run("Running generateKeyPair returns 'keypair generated'", func(t *testing.T) {
		cmd := e.Cmd
		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"generateKeyPair", "legalEntity"})
		cmd.SetOutput(buf)
		err := cmd.Execute()

		if err != nil {
			t.Errorf("Expected no error, got [%s]", err.Error())
		}

		expected := "KeyPair generated\n"
		if buf.String() != expected {
			t.Errorf("Expected output [%s], got [%s]", expected, buf.String())
		}
	})

	t.Run("Running publicKey with too few arguments gives error", func(t *testing.T) {
		cmd := e.Cmd

		cmd.SetArgs([]string{"publicKey"})
		cmd.SetOutput(new(bytes.Buffer))
		err := cmd.Execute()

		if err == nil {
			t.Error("Expected error, got nothing")
		}

		expected := "requires a URI argument"
		if err.Error() != expected {
			t.Errorf("Expected error [%s], got [%s]", expected, err.Error())
		}
	})

	t.Run("Running publicKey returns error if public key does not exist", func(t *testing.T) {
		cmd := e.Cmd
		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"publicKey", "legalEntityMissing"})
		cmd.SetOutput(buf)
		err := cmd.Execute()

		if err != nil {
			t.Errorf("Expected no error, got [%s]", err.Error())
		}

		expected := "Error printing publicKey: could not open private key for legalEntity: {legalEntityMissing} with filename ../temp/bGVnYWxFbnRpdHlNaXNzaW5n_private.pem\n"
		if buf.String() != expected {
			t.Errorf("Expected output [%s], got [%s]", expected, buf.String())
		}
	})

	t.Run("Running publicKey returns pem", func(t *testing.T) {
		c.GenerateKeyPairFor(types.LegalEntity{URI: "legalEntity"})
		cmd := e.Cmd
		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"publicKey", "legalEntity"})
		cmd.SetOutput(buf)
		err := cmd.Execute()

		if err != nil {
			t.Errorf("Expected no error, got [%s]", err.Error())
		}

		expected := "-----BEGIN PUBLIC KEY-----"
		if strings.Index(buf.String(), expected) != 0 {
			t.Errorf("Expected output to begin with [%s], got [%s]", expected, buf.String())
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
		cmd.SetOutput(buf)

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