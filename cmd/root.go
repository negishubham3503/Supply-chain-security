package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "supply-chain-security",
	Short: "this is a security utilty tool for software composition analysis",
	Long:  "A CLI-tool to help you find security shortcomings related to dependency, commits and commit authors",
	Run:   func(cmd *cobra.Command, args []string) {},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Oops. An error while executing the tool '%s'\n", err)
		os.Exit(1)
	}
}
