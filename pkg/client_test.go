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

package pkg

import (
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"reflect"
	"sync"
	"testing"
)

func TestNewCryptoClient(t *testing.T) {
	t.Run("returns defaultCryptoEngine by default", func(t *testing.T) {
		cc := NewCryptoClient()

		if reflect.TypeOf(cc).String() != "*pkg.Crypto" {
			t.Errorf("Expected CryptoClient to be of type *pkg.Crypto, got %s", reflect.TypeOf(cc))
		}
	})

	t.Run("panics for illegal config", func(t *testing.T) {
		instance := CryptoInstance()
		instance.Config.Keysize = 1
		instance.configDone = false
		instance.configOnce = sync.Once{}

		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic")
			}
			instance.Config.Keysize = types.ConfigKeySizeDefault
			instance.configDone = false
			instance.configOnce = sync.Once{}
		}()

		NewCryptoClient()
	})
}
