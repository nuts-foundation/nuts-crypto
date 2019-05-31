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

package storage

import (
	types "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/spf13/viper"
	"reflect"
	"testing"
)

func TestNewCryptoBackend(t *testing.T) {
	t.Run("Getting the backend returns the fs backend", func(t *testing.T) {
		viper.Set(types.ConfigStorage, types.ConfigStorageFs)

		cl, err := NewCryptoStorage()

		if err != nil {
			t.Errorf("Expected no error, got %s", err.Error())
		}

		if reflect.TypeOf(cl).String() != "*storage.fileSystemBackend" {
			t.Errorf("Expected crypto backend to be of type [*storage.fileSystemBackend], Got [%s]", reflect.TypeOf(cl).String())
		}
	})

	t.Run("Getting the backend returns err for unknown backend", func(t *testing.T) {
		viper.Set(types.ConfigStorage, "unknown")

		_, err := NewCryptoStorage()

		if err == nil {
			t.Errorf("Expected error, got nothing")
		}

		if err.Error() != "-: Only fs backend available for now" {
			t.Errorf("Expected error [-: Only fs backend available for now], Got [%s]", err.Error())
		}
	})
}