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
	"crypto/rsa"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/backend"
	"os"
	"testing"
)

func TestNewCryptoClient(t *testing.T) {
	t.Run("New returns a fileSystemClient with default path", func(t *testing.T) {
		client, err := NewCryptoClient()

		if client == nil {
			t.Errorf("Expected CryptoClient, Got nil: %s", err.Error())
		}
	})
}

func TestFileSystemClient_GenerateKeyPair(t *testing.T) {
	t.Run("A new key pair is stored at config location", func(t *testing.T) {
		client := createTempClient()

		err := client.GenerateKeyPair(types.LegalEntity{"https://nuts.nl/identities/agbcode#00000000"})

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		emptyTemp()
	})

	t.Run("A new key pair is stored in the cache", func(t *testing.T) {
		client := createTempClient()

		client.GenerateKeyPair(types.LegalEntity{"https://nuts.nl/identities/agbcode#00000000"})

		entries := len(client.keyCache)
		if entries != 1 {
			t.Errorf("Expected 1 entry in cache, Got %d", entries)
		}

		emptyTemp()
	})
}

func TestFileSystemClient_DecryptCipherTextFor(t *testing.T) {
	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		client := createTempClient()

		legalEntity := types.LegalEntity{Uri: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPair(legalEntity)

		cipherText, err := client.EncryptPlainTextFor([]byte(plaintext), legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		decryptedText, err := client.DecryptCipherTextFor(cipherText, legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
		}

		if string(decryptedText) != plaintext {
			t.Errorf("Expected decrypted text to match [%s], Got [%s]", plaintext, decryptedText)
		}

		emptyTemp()
	})

	t.Run("decryption for unknown legalEntity gives error", func(t *testing.T) {
		client := createTempClient()

		legalEntity := types.LegalEntity{Uri: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPair(legalEntity)

		_, err := client.EncryptPlainTextFor([]byte(plaintext), legalEntity)

		if err != nil {
			t.Errorf("Expected no error, Got %s", err.Error())
			return
		}

		_, err = client.DecryptCipherTextFor([]byte(""), types.LegalEntity{Uri: "other"})

		if err.Error() != "open ../../temp/b3RoZXI=_private.pem: no such file or directory" {
			t.Errorf("Expected error [open ../../temp/b3RoZXI=_private.pem: no such file or directory], Got [%s]", err.Error())
		}

		emptyTemp()
	})
}

func TestFileSystemClient_EncryptPlainTextFor(t *testing.T) {
	t.Run("encryption for unknown legalEntity gives error", func(t *testing.T) {
		client := createTempClient()

		legalEntity := types.LegalEntity{Uri: "test"}
		plaintext := "for your eyes only"

		_, err := client.EncryptPlainTextFor([]byte(plaintext), legalEntity)

		if err == nil {
			t.Errorf("Expected error, Got nothing")
			return
		}

		if err.Error() != "open ../../temp/dGVzdA==_private.pem: no such file or directory" {
			t.Errorf("Expected error [open ../../temp/dGVzdA==_private.pem: no such file or directory], Got [%s]", err.Error())
		}

		emptyTemp()
	})
}

func TestFileSystemClient_DecryptKeyAndCipherTextFor(t *testing.T) {
	t.Run("Encrypted text can be decrypted again", func(t *testing.T) {
		client := createTempClient()

		legalEntity := types.LegalEntity{Uri: "test"}
		plaintext := "for your eyes only"

		client.GenerateKeyPair(legalEntity)

		encRecord, err := client.EncryptKeyAndPlainTextFor([]byte(plaintext), legalEntity)

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

		emptyTemp()
	})
}

func createTempClient() cryptoClient {
	client := cryptoClient{
		backend: createTempBackend(),
		keyCache: make(map[string]rsa.PrivateKey),
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
