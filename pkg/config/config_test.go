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
