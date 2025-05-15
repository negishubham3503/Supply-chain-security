package cmd

import (
	"context"
	"fmt"
	"os"
	"supply-chain-security/types"
	"supply-chain-security/util"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var repoURL string

var repositoryCmd = &cobra.Command{
	Use:     "repository",
	Aliases: []string{"repo"},
	Short:   "Analyze the lockfile of repository",
	Long:    "This command analyzes the commits made to the lockfile of the repository.",
	Run: func(cmd *cobra.Command, args []string) {

		if repoURL == "" {
			fmt.Println("Error: --url flag is required")
			return
		}

		fmt.Printf("Starting Authenticated Github Client...\n")
		ctx := context.Background()
		_ = godotenv.Load()

		token := os.Getenv("GITHUB_ACCESS_TOKEN")
		if token == "" {
			panic("Github Token Not set")
		}

		client := util.NewGitHubClient(ctx, token)
		fmt.Printf("✅ Github Client Started\n")

		owner, repo, err := util.ParseGitHubURL(repoURL)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Finding Lockfile in Repo...\n")

		file, err := util.FindLockfile(ctx, client, owner, repo)
		if err != nil {
			fmt.Printf("Could not find lockfile || lockfile not supported")
			panic(err)
		}

		fmt.Printf("✅ Lockfile Found --> %s\n", file)

		fmt.Printf("Finding commits in %s\n", file)
		commits, err := util.GetLockFileCommits(ctx, client, owner, repo, file)
		if err != nil {
			fmt.Printf("Error getting commits: %v\n", err)
			panic(err)
		}

		fmt.Printf("✅ Commits Found\n")

		var allRepoCommitRisks []types.CommitRisk

		fmt.Printf("Starting Commits Analysis...\n")

		for i, commit := range commits {
			fmt.Printf("Commit #%d\n", i)
			sha := commit.GetSHA()
			commit_author := commit.GetCommit().GetAuthor().GetLogin()
			commit_date := commit.GetCommit().GetAuthor().GetDate()

			content, err := util.FetchFileAtCommit(ctx, client, owner, repo, file, sha)
			if err != nil {
				fmt.Printf("Error reading file at %s: %v\n", sha, err)
				panic(err)
			}

			authorId := fmt.Sprintf("%d", commit.GetAuthor().GetID())
			author := types.Author{
				ID:   authorId,
				Name: commit_author,
			}

			var emptyFiles []types.File // need a way to add files here
			formattedCommit := types.Commit{
				Sha:     sha,
				Date:    commit_date.String(),
				Author:  author,
				Message: commit.GetCommit().GetMessage(),
				Files:   emptyFiles, // reference added files here
			}

			packageUrls := util.ExtractPackages(file, content)

			commitRisk, err := util.EvaluateRiskByCommit(formattedCommit, packageUrls)
			if err != nil {
				fmt.Printf("Error evaluating risk for commit %s: %s", sha, err)
			} else {
				allRepoCommitRisks = append(allRepoCommitRisks, commitRisk)
			}
		}
		fmt.Printf("✅ Finished Commit Analysis, here are the results -\n")
		for i, commitRisk := range allRepoCommitRisks {
			fmt.Printf("%d | %s | %s\n", i, commitRisk.Commit.Sha, commitRisk.Score)
		}
	},
}

func init() {
	repositoryCmd.Flags().StringVarP(&repoURL, "url", "u", "", "GitHub repository URL (required)")
	repositoryCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(repositoryCmd)
}
