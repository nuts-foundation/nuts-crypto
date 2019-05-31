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

package crypto

import (
	"reflect"
	"testing"
)

func TestNewCryptoClient(t *testing.T) {
	t.Run("returns defaultCryptoEngine by default", func(t *testing.T) {
		cc := NewCryptoClient()

		if reflect.TypeOf(cc).String() != "*crypto.DefaultCryptoBackend" {
			t.Errorf("Expected CryptoClient to be of type *crypto.DefaultCryptoBackend, got %s", reflect.TypeOf(cc))
		}
	})
}
