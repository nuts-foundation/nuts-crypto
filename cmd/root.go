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

package cmd

import (
	goflag "flag"
	"github.com/nuts-foundation/nuts-crypto/pkg/engine"
	flag "github.com/spf13/pflag"
)

var e = engine.NewCryptoEngine()
var rootCmd = e.Cmd()

func Execute() {
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	goflag.Parse()

	if err := e.Configure(); err != nil {
		panic(err)
	}

	rootCmd.Execute()
}
