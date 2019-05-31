/*
 * Nuts crypto
 * Copyright (C) 2019 Nuts community
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

package crypto

import (
	"bytes"
	"github.com/golang/mock/gomock"
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-go/mock"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

func TestNewCryptoEngine_Configure(t *testing.T) {
	t.Run("Configure returns an error when keySize is too small", func(t *testing.T) {
		e := NewCryptoEngine()
		viper.Set(types.ConfigKeySize, 2047)
		err := e.Configure()

		if err == nil {
			t.Errorf("Expected error, got nothing")
		}

		if err.Error() != "-: invalid keySize, needs to be at least 2048 bits" {
			t.Errorf("Expected error [-: invalid keySize, needs to be at least 2048 bits], got %s", err.Error())
		}
	})
}

func TestNewryptoEngine_FlagSet(t *testing.T) {
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
