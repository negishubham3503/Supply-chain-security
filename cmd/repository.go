package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"supply-chain-security/types"
	"supply-chain-security/util"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var (
	repoURL          string
	commitFlag       bool
	commitAuthorFlag bool
	jsonFlag         bool
)

var repositoryCmd = &cobra.Command{
	Use:     "risk",
	Aliases: []string{"risk"},
	Short:   "Analyze the lockfile of repository",
	Long:    "This command analyzes the commits made to the lockfile of the repository.",
	Run: func(cmd *cobra.Command, args []string) {

		var completeSCAJson types.SCA

		if repoURL == "" {
			fmt.Println("Error: --url or -u flag is required")
			return
		}

		if !commitFlag && !commitAuthorFlag {
			fmt.Println("Error: you must atleast specify --commit or --author flag")
			return
		}

		if commitFlag {
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

			completeSCAJson.Repo = repo
			completeSCAJson.Owner = owner
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
				commit_author := commit.GetAuthor().GetLogin()
				commit_date := commit.GetCommit().GetAuthor().GetDate()

				content, err := util.FetchFileAtCommit(ctx, client, owner, repo, file, sha)
				if err != nil {
					fmt.Printf("Error reading file at %s: %v\n", sha, err)
					panic(err)
				}

				authorId := fmt.Sprintf("%d", commit.GetAuthor().GetID())
				authorID, err := strconv.Atoi(authorId)
				if err != nil {
					fmt.Println("Error:", err)
					return
				}

				author := types.Author{
					ID:   authorID,
					Name: commit_author,
				}

				//var emptyFiles []types.File // need a way to add files here
				formattedCommit := types.Commit{
					Sha:     sha,
					Date:    commit_date.String(),
					Author:  author,
					Message: commit.GetCommit().GetMessage(),
					//Files:   emptyFiles, // reference added files here
				}

				packageUrls := util.ExtractPackages(file, content)

				commitRisk, err := util.EvaluateRiskByCommit(formattedCommit, packageUrls)
				if err != nil {
					fmt.Printf("Error evaluating risk for commit %s: %s", sha, err)
				} else {
					allRepoCommitRisks = append(allRepoCommitRisks, commitRisk)
				}
			}
			fmt.Printf("Starting Code level Commit Risk Analysis...\n")
			var repository types.Repo
			repository.Name = repo
			repository.Owner = owner
			allRepoCommitRisks = util.FormCompleteCombinedCommitRisksByRepo(repository, allRepoCommitRisks)
			fmt.Printf("✅ Finished Commit Analysis, here are the results -\n")
			for i, commitRisk := range allRepoCommitRisks {
				allRepoCommitRisks[i].Score = util.GetRiskRating(commitRisk.Score)
				//fmt.Printf("%d | %s | %s\n", i, commitRisk.Commit.Sha, util.GetRiskRating(commitRisk.Score))
			}

			completeSCAJson.CommitRisks = allRepoCommitRisks
			util.SaveSlice(allRepoCommitRisks, "data.json")
		}

		if commitAuthorFlag {
			fmt.Printf("Starting Author Risk Analysis...\n")
			owner, repo, err := util.ParseGitHubURL(repoURL)
			if err != nil {
				panic(err)
			}
			var repository types.Repo
			repository.Name = repo
			repository.Owner = owner
			authorList := util.GetAuthorsByRepo(repository)

			fmt.Println(authorList)

			var allAuthorsRisk []types.AuthorRisk
			allRepoCommitRisks := util.LoadSlice()
			for _, author := range authorList {
				fmt.Printf("Author #%s\n", author.Name)
				authorRisk := util.EvaluateRiskByAuthor(author, allRepoCommitRisks)
				allAuthorsRisk = append(allAuthorsRisk, authorRisk)
			}

			fmt.Printf("✅ Finished Author Risk Analysis, here are the results -\n")
			for i, authorRisk := range allAuthorsRisk {
				allAuthorsRisk[i].Score = util.GetAuthorRiskScore(authorRisk.Score)
				fmt.Printf("%d | %s | %s\n", i, authorRisk.Author.Name, allAuthorsRisk[i].Score)
			}

			completeSCAJson.AuthorRisks = allAuthorsRisk
			util.SaveSlice(completeSCAJson, "sca.json")
		}
	},
}

func init() {
	repositoryCmd.Flags().StringVarP(&repoURL, "url", "u", "", "GitHub repository URL (required)")
	repositoryCmd.MarkFlagRequired("url")
	repositoryCmd.Flags().BoolVarP(&commitFlag, "commit", "c", false, "Analyze Commit Risks")
	repositoryCmd.Flags().BoolVarP(&commitAuthorFlag, "author", "a", false, "Analyze Commit Author Risk")
	repositoryCmd.Flags().BoolVarP(&jsonFlag, "json", "j", false, "Output in JSON")

	rootCmd.AddCommand(repositoryCmd)
}
