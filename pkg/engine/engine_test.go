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

package engine

import (
	"bytes"
	"crypto/rsa"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/backend"
	"github.com/nuts-foundation/nuts-go/mock"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestNewCryptoEngine(t *testing.T) {
	t.Run("New returns a fileSystemClient with default keySize", func(t *testing.T) {
		client := NewCryptoEngine()

		if client.keySize != types.ConfigKeySizeDefault {
			t.Errorf("Expected default keySize 2048, Got %d", client.keySize)
		}
	})
}

func TestCryptoEngine_GenerateKeyPair(t *testing.T) {
	t.Run("A new key pair is stored at config location", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		err := client.GenerateKeyPairFor(types.LegalEntity{"https://nuts.nl/identities/agbcode#00000000"})

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}
	})

	//t.Run("A new key pair is stored in the cache", func(t *testing.T) {
	//	client := createTempEngine()
	//	defer emptyTemp()
	//
	//	client.GenerateKeyPairFor(types.LegalEntity{"https://nuts.nl/identities/agbcode#00000000"})
	//
	//	entries := len(client.keyCache)
	//	if entries != 1 {
	//		t.Errorf("Expected 1 entry in cache, Got %d", entries)
	//	}
	//})

	t.Run("A keySize too small generates an error", func(t *testing.T) {
		client := DefaultCryptoEngine{
			backend: createTempBackend(),
			//keyCache: make(map[string]rsa.PrivateKey),
			keySize: 10,
		}

		err := client.GenerateKeyPairFor(types.LegalEntity{"https://nuts.nl/identities/agbcode#00000000"})
		defer emptyTemp()

		if err == nil {
			t.Errorf("Expected error got nothing")
		} else if err.Error() != "crypto/rsa: too few primes of given length to generate an RSA key" {
			t.Errorf("Expected error [crypto/rsa: too few primes of given length to generate an RSA key] got: [%s]", err.Error())
		}
	})
}

func TestCryptoEngine_DecryptCipherTextFor(t *testing.T) {
	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPairFor(legalEntity)

		cipherText, err := client.encryptPlainTextFor([]byte(plaintext), legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		decryptedText, err := client.decryptCipherTextFor(cipherText, legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if string(decryptedText) != plaintext {
			t.Errorf("Expected decrypted text to match [%s], Got [%s]", plaintext, decryptedText)
		}
	})

	t.Run("decryption for unknown legalEntity gives error", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPairFor(legalEntity)

		_, err := client.encryptPlainTextFor([]byte(plaintext), legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
			return
		}

		_, err = client.decryptCipherTextFor([]byte(""), types.LegalEntity{URI: "other"})

		if err.Error() != "open ../../temp/b3RoZXI=_private.pem: no such file or directory" {
			t.Errorf("Expected error [open ../../temp/b3RoZXI=_private.pem: no such file or directory], Got [%s]", err.Error())
		}
	})
}

func TestCryptoEngine_encryptPlainTextFor(t *testing.T) {
	t.Run("encryption for unknown legalEntity gives error", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"

		_, err := client.encryptPlainTextFor([]byte(plaintext), legalEntity)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
			return
		}

		if err.Error() != "open ../../temp/dGVzdA==_private.pem: no such file or directory" {
			t.Errorf("Expected error [open ../../temp/dGVzdA==_private.pem: no such file or directory], Got [%s]", err.Error())
		}
	})
}

func TestCryptoEngine_DecryptKeyAndCipherTextFor(t *testing.T) {
	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPairFor(legalEntity)
		pubKey, _ := client.backend.GetPublicKey(legalEntity)

		encRecord, err := client.EncryptKeyAndPlainTextWith([]byte(plaintext), []rsa.PublicKey{*pubKey})

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		decryptedText, err := client.DecryptKeyAndCipherTextFor(encRecord, legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if string(decryptedText) != plaintext {
			t.Errorf("Expected decrypted text to match [%s], Got [%s]", plaintext, decryptedText)
		}
	})
}

func TestDefaultCryptoEngine_VerifyWith(t *testing.T) {
	t.Run("A signed piece of data can be verified", func(t *testing.T) {
		data := []byte("hello")
		legalEntity := types.LegalEntity{URI: "test"}
		client := createTempEngine()
		client.GenerateKeyPairFor(legalEntity)
		defer emptyTemp()

		sig, err := client.SignFor(data, legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		pub, err := client.backend.GetPublicKey(legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		bool, err := client.VerifyWith(data, sig, pub)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if !bool {
			t.Error("Expected signature to be valid")
		}
	})
}

func TestCryptoEngine_ExternalIdFor(t *testing.T) {
	t.Run("ExternalId creates same Id for given identifier and legalEntity", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		client.GenerateKeyPairFor(legalEntity)
		subject := "test_patient"

		bytes1, err := client.ExternalIdFor([]byte(subject), legalEntity)
		bytes2, err := client.ExternalIdFor([]byte(subject), legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if !reflect.DeepEqual(bytes1, bytes2) {
			t.Errorf("Expected externalIds to be equals")
		}
	})

	t.Run("ExternalId generates error for unknown legalEntity", func(t *testing.T) {
		client := createTempEngine()
		defer emptyTemp()

		legalEntity := types.LegalEntity{URI: "test"}
		subject := "test_patient"

		_, err := client.ExternalIdFor([]byte(subject), legalEntity)

		if err == nil {
			t.Errorf("Expected error, got nothing")
		}

		if err.Error() != "open ../../temp/dGVzdA==_private.pem: no such file or directory" {
			t.Errorf("Expected error [open ../../temp/dGVzdA==_private.pem: no such file or directory], got %s", err.Error())
		}
	})
}

func TestDefaultCryptoEngine_PublicKey(t *testing.T) {
	t.Run("A signed piece of data can be verified", func(t *testing.T) {
		legalEntity := types.LegalEntity{URI: "test"}
		client := createTempEngine()
		client.GenerateKeyPairFor(legalEntity)
		defer emptyTemp()

		pub, err := client.PublicKey(legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if pub == nil {
			t.Error("Expected public key, got nothing")
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

func TestCryptoEngine_Cmd(t *testing.T) {
	t.Run("Cmd returns a command with a single subCommand", func(t *testing.T) {
		e := NewCryptoEngine()
		cmd := e.Cmd()

		if cmd.Name() != "crypto" {
			t.Errorf("Expected Cmd name to equal [crypto], got %s", cmd.Name())
		}

		if len(cmd.Commands()) != 2 {
			t.Errorf("Expected Cmd to have 1 sub-command, got %d", len(cmd.Commands()))
		}
	})
}

func TestCryptoEngine_Configure(t *testing.T) {
	t.Run("Configure returns an error when keySize is too small", func(t *testing.T) {
		e := NewCryptoEngine()
		viper.Set(types.ConfigKeySize, 2047)
		err := e.Configure()

		if err == nil {
			t.Errorf("Expected error, got nothing")
		}

		if err.Error() != "invalid keySize, needs to be at least 2048 bits" {
			t.Errorf("Expected error [invalid keySize, needs to be at least 2048 bits], got %s", err.Error())
		}
	})
}

func TestCryptoEngine_FlagSet(t *testing.T) {
	t.Run("Cobra help should list flags", func(t *testing.T) {
		e := NewCryptoEngine()
		cmd := newRootCommand()
		cmd.Flags().AddFlagSet(e.FlagSet())
		cmd.SetArgs([]string{"--help"})

		buf := new(bytes.Buffer)
		cmd.SetOutput(buf)

		_, err := cmd.ExecuteC()

		if err != nil {
			t.Errorf("Expected no error, got %s", err.Error())
		}

		result := buf.String()
		println(result)
		if !strings.Contains(result, "--cryptobackend") {
			t.Errorf("Expected --cryptobackend to be command line flag")
		}

		if !strings.Contains(result, "--fspath") {
			t.Errorf("Expected --fspath to be command line flag")
		}

	})
}

func TestCryptoEngine_Routes(t *testing.T) {
	t.Run("Registers the 4 available routes", func(t *testing.T) {
		se := createTempEngine()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockEchoRouter(ctrl)

		echo.EXPECT().POST("/crypto/sign", gomock.Any())
		echo.EXPECT().POST("/crypto/verify", gomock.Any())
		echo.EXPECT().POST("/crypto/decrypt", gomock.Any())
		echo.EXPECT().POST("/crypto/encrypt", gomock.Any())
		echo.EXPECT().POST("/crypto/external_id", gomock.Any())
		echo.EXPECT().POST("/crypto/generate", gomock.Any())

		se.Routes(echo)
	})
}

func createTempEngine() DefaultCryptoEngine {
	client := DefaultCryptoEngine{
		backend: createTempBackend(),
		//keyCache: make(map[string]rsa.PrivateKey),
		keySize: types.ConfigKeySizeDefault,
	}

	return client
}

func createTempBackend() backend.Backend {
	b, _ := backend.NewFileSystemBackend("../../temp")
	return b
}

func emptyTemp() {
	err := os.RemoveAll("../../temp/")

	if err != nil {
		println(err.Error())
	}
}
