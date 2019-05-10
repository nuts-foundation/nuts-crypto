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

package config

import (
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/spf13/pflag"
)

// Use to add config flags to your Cobra command
//  cmd.Flags().AddFlagSet(Flags())
func Flags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	flags.String(types.ConfigBackend, types.ConfigBackendFs, "backend to use, 'fs' for file system (default)")
	flags.String(types.ConfigFSPath, types.ConfigFSPathDefault, "when file system is used as backend, this configures the path where keys are stored (default .)")
	flags.Int(types.ConfigKeySize, types.ConfigKeySizeDefault, "number of bits to use when creating new RSA keys")

	return flags
}
