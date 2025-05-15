package util

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"supply-chain-security/config"
	"supply-chain-security/types"
)

const baseUrl = config.GithubApiBaseUrl

var allPublicRepositories = GetAllRepos()

func GetAllRepos() []types.Repo {
	var allRepos []types.Repo
	since := 0 // Start from the beginning

	for {
		url := fmt.Sprintf("%s/repositories?since=%d", baseUrl, since)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("Error fetching repositories:", err)
			break
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var repos []types.Repo
		json.Unmarshal(body, &repos)

		if len(repos) == 0 {
			break // No more repositories
		}

		allRepos = append(allRepos, repos...)
		since = repos[len(repos)-1].ID // Get last repo ID for next request
	}

	return allRepos
}

func GetAuthorsByRepo(repo types.Repo) []types.Author {
	var allAuthors []types.Author
	page := 1

	for {
		url := fmt.Sprintf("%s/repos/%s/%s/contributors?per_page=100&page=%d", baseUrl, repo.Owner, repo.Name, page)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("Error fetching authors for the provided repo: ", repo.Name, err)
			break
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var authors []types.Author
		json.Unmarshal(body, &authors)

		if len(authors) == 0 {
			break // No more authors
		}

		allAuthors = append(allAuthors, authors...)
		page++
	}

	return allAuthors
}

func CheckAuthorinRepoContributors(repo types.Repo, author types.Author) bool {
	var contributors = GetAuthorsByRepo(repo)
	for _, contributor := range contributors {
		if author.ID == contributor.ID && author.Name == contributor.Name {
			return true
		}
	}
	return false
}

func GetReposByAuthor(author types.Author) []types.Repo {
	var repos []types.Repo
	for _, repo := range allPublicRepositories {
		if CheckAuthorinRepoContributors(repo, author) == true {
			repos = append(repos, repo)
		}
	}
	return repos
}

func EvaluateRiskByAuthor(author types.Author, allCommitRisksInRepo []types.CommitRisk) types.AuthorRisk {
	var authorRisk types.AuthorRisk
	authorRisk.Author = author
	authorRisk.Score = ""
	for _, commitRisk := range allCommitRisksInRepo {
		if author == commitRisk.Commit.Author {
			authorRisk.Score = authorRisk.Score + commitRisk.Score + ";"
		}
	}
	return authorRisk
}

// we need to create a database of the authors and its commits and then our underlying script
// references the database and gives the rating.
// To update the database we have to constanlty run the cli in some sort of batch job in clou

//another possible way is to take github security advisory as a base and query everything on it
// for example security advisory the source repo, the commit who made it etc
// and these details should be stored in our database. So when a user enters a repo we first query our database
// if nothing found then usual source code analysis through getting all commits and running analyzer on that
