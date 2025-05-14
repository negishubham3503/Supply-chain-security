package cmd

import (
	"context"
	"fmt"
	"os"
	"supply-chain-security/util"

	"github.com/joho/godotenv"

	"github.com/spf13/cobra"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Get SBOM from repo",
	Long:  "Enter your repository URL to retrieve SPDX format SBOM",
	Run: func(cmd *cobra.Command, args []string) {

		if repoURL == "" {
			fmt.Println("Error: --url flag is required")
			return
		}

		ctx := context.Background()
		_ = godotenv.Load()

		token := os.Getenv("GITHUB_ACCESS_TOKEN")
		if token == "" {
			panic("Github Token Not set")
		}

		client := util.NewGitHubClient(ctx, token)

		owner, repo, err := util.ParseGitHubURL(repoURL)
		if err != nil {
			panic(err)
		}

		purls, err := util.FetchDependenciesViaSBOM(ctx, client, owner, repo)
		if err != nil {
			panic("SBOM Dependency didnt work")
		}

		for _, purl := range purls {
			fmt.Printf("%s\n", purl)
		}
	},
}

func init() {
	sbomCmd.Flags().StringVarP(&repoURL, "url", "u", "", "GitHub repository URL (required)")
	sbomCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(sbomCmd)
}
