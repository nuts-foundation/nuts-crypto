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
	"bytes"
	"github.com/spf13/cobra"
	"strings"
	"testing"
)

func newRootCommand() *cobra.Command {
	testRootCommand := &cobra.Command{
		Use: "root",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}

	return testRootCommand
}

func TestFlags(t *testing.T) {
	t.Run("Cobra help should list flags", func(t *testing.T) {
		cmd := newRootCommand()
		cmd.Flags().AddFlagSet(Flags())
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
