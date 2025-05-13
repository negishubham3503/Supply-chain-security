package cmd

import (
	"github.com/spf13/cobra"
)

var riskCmd = &cobra.Command{
	Use:     "risk",
	Aliases: []string{"risk"},
	Long:    "Enter your repository URL to retrieve the risk rating based on commits or authors",
	Run:     GetRiskByRepoCommits,
}

func GetRiskByRepoCommits(cmd *cobra.Command, args []string) {
}

func init() {
	rootCmd.AddCommand(riskCmd)
}
