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
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/nuts-foundation/nuts-crypto/pkg/generated"
	engine "github.com/nuts-foundation/nuts-go/pkg"
)

// NewCryptoEngine the engine configuration for nuts-go.
func NewCryptoEngine() *engine.Engine {
	cb := CryptoBackend()

	return &engine.Engine {
		Cmd: cb.Cmd(),
		Configure: cb.Configure,
		FlagSet:FlagSet(),
		Name: "Crypto",
		Routes: func(router runtime.EchoRouter) {
			generated.RegisterHandlers(router, cb)
		},
	}
}