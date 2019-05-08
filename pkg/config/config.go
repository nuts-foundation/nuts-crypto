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

	return flags
}
