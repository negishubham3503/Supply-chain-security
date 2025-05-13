package cmd

import (
	"context"
	"fmt"
	"os"
	"supply-chain-security/config"
	"supply-chain-security/util"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

const baseUrl = config.GithubApiBaseUrl + "repos"

var repoURL string

var repositoryCmd = &cobra.Command{
	Use:     "repository",
	Aliases: []string{"repo"},
	Short:   "Analyze a GitHub repository",
	Long:    "Enter your repository URL to retrieve general repository overview",
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

		file, err := util.FindLockfile(ctx, client, owner, repo)
		if err != nil {
			fmt.Printf("Could not find lockfile || lockfile not supported")
			panic(err)
		}

		fmt.Printf("\nChecking commits for %s\n", file)
		commits, err := util.GetLockFileCommits(ctx, client, owner, repo, file)
		if err != nil {
			fmt.Printf("Error getting commits: %v\n", err)
			panic(err)
		}

		for i, commit := range commits {
			sha := commit.GetSHA()
			commit_author := commit.GetCommit().GetAuthor().GetLogin()
			commit_date := commit.GetCommit().GetAuthor().GetDate()

			content, err := util.FetchFileAtCommit(ctx, client, owner, repo, file, sha)
			if err != nil {
				fmt.Printf("Error reading file at %s: %v\n", sha, err)
				panic(err)
			}

			packageUrls := util.ExtractPackages(file, content)

			// This requires work
			for _, purl := range packageUrls {
				//evaluate Risk Code
				fmt.Printf("Risk for %s - Not Implemented\n", purl)
			}
			fmt.Printf("\n\n-------------\n\n")

			fmt.Printf("Commit - %d | Made by - %s | At time - %s\n", i, commit_author, commit_date.Format(time.RFC3339))
		}

	},
}

func init() {
	repositoryCmd.Flags().StringVarP(&repoURL, "url", "u", "", "GitHub repository URL (required)")
	repositoryCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(repositoryCmd)
}
