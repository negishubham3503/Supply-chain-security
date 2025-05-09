package cmd

import (
	"context"
	"fmt"
	"net/url"
	"supply-chain-security/config"
	"supply-chain-security/util"

	"github.com/google/go-github/github"
	"github.com/spf13/cobra"
)

var supportedFiles = []string{
	"go.sum",
	"package-lock.json",
	"requirements.txt",
}

const baseUrl = config.GithubApiBaseUrl + "repos"

var repositoryCmd = &cobra.Command{
	Use:     "repository",
	Aliases: []string{"repo"},
	Long:    "Enter your repository URL to retrieve general repository overview",
	Run: func(cmd *cobra.Command, args []string) {

		parsedUrl, err := url.Parse(args[0])
		if err != nil {
			fmt.Println("Error parsing the repository URL that you entered")
			return
		}
		repoUrl := baseUrl + parsedUrl.Path

		ctx := context.Background()
		client := github.NewClient(nil)

		owner, repo, err := util.ParseGitHubURL(repoUrl)
		if err != nil {
			panic(err)
		}

		branch, err := util.GetDefaultBranch(ctx, client, owner, repo)
		if err != nil {
			panic(err)
		}

		seenPURLs := make(map[string]struct{})

		for _, file := range supportedFiles {
			if !util.FileExists(ctx, client, owner, repo, branch, file) {
				fmt.Printf("Skipping %s: not found\n", file)
				continue
			}

			fmt.Printf("\nChecking commits for %s\n", file)
			commits, err := util.ListCommitsTouchingFile(ctx, client, owner, repo, branch, file)
			if err != nil {
				fmt.Printf("Error getting commits: %v\n", err)
				continue
			}

			var lastPkgs []string

			for _, commit := range commits {
				sha := commit.GetSHA()
				content, err := util.FetchFileAtCommit(ctx, client, owner, repo, file, sha)
				if err != nil {
					fmt.Printf("Error reading file at %s: %v\n", sha, err)
					continue
				}

				pkgs := util.ExtractPackages(file, content)
				added := util.DiffPkgLists(lastPkgs, pkgs)
				for _, a := range added {
					if _, ok := seenPURLs[a]; !ok {
						seenPURLs[a] = struct{}{}
						fmt.Println("Added:", a)
					}
				}
				lastPkgs = pkgs

				fmt.Printf("Commit %s\n", sha)
				fmt.Printf("File content (first 200 chars):\n%s\n\n", content[:min(len(content), 200)])
				fmt.Printf("Parsed %d packages\n", len(pkgs))
			}

		}

		fmt.Println("\n✅ Unique dependencies found:")
		for p := range seenPURLs {
			fmt.Println(p)
		}

		// resp, err := http.Get(repoUrl)
		// if err != nil {
		// 	fmt.Println("There is some issue while fetching details from the repository URL")
		// 	return
		// }
		// defer resp.Body.Close()

		// body, err := io.ReadAll(resp.Body)
		// if err != nil {
		// 	fmt.Println("There is some issue while fetching details from the repository URL")
		// 	return
		// }

		// gitrepo := GitHubRepo{}
		// json.Unmarshal(body, &gitrepo)

		// prettified, err := json.MarshalIndent(gitrepo, "", "\t")
		// if err != nil {
		// 	fmt.Println(err)
		// }
		// fmt.Println(string(prettified))

		// err = os.WriteFile("repo.json", prettified, 0644)
		// if err != nil {
		// 	fmt.Println("There is some issue while saving response to file")
		// 	return
		// }

	},
}

func init() {
	rootCmd.AddCommand(repositoryCmd)
}
