package util

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"supply-chain-security/config"
	"supply-chain-security/types"

	"github.com/joho/godotenv"
)

const baseUrl = config.GithubApiBaseUrl

var allPublicRepositories = GetAllRepos()

func GetAllRepos() []types.Repo {
	var allRepos []types.Repo
	since := 0 // Start from the beginning

	for {
		token := os.Getenv("GITHUB_ACCESS_TOKEN")
		url := fmt.Sprintf("%s/repositories?since=%d", baseUrl, since)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			os.Exit(1)
		}

		req.Header.Add("Authorization", "token "+token)

		client := &http.Client{}
		resp, err := client.Do(req)
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
		_ = godotenv.Load()
		token := os.Getenv("GITHUB_ACCESS_TOKEN")
		url := fmt.Sprintf("%s/repos/%s/%s/contributors?per_page=100&page=%d", baseUrl, repo.Owner, repo.Name, page)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			os.Exit(1)
		}

		req.Header.Add("Authorization", "token "+token)

		client := &http.Client{}
		resp, err := client.Do(req)
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
		} else {
			authorRisk.Score = "No-Risk"
		}
	}
	return authorRisk
}

const filePath = "data.json"

func SaveSlice[T []types.CommitRisk | types.SCA](allRepoCommitRisks T, filePath string) {
	file, _ := os.Create(filePath)
	defer file.Close()
	json.NewEncoder(file).Encode(allRepoCommitRisks)
}

func LoadSlice() []types.CommitRisk {
	file, err := os.Open(filePath)
	if err != nil {
		return []types.CommitRisk{} // Return empty slice if file doesn't exist
	}
	defer file.Close()

	var allRepoCommitRisks []types.CommitRisk
	json.NewDecoder(file).Decode(&allRepoCommitRisks)
	return allRepoCommitRisks
}

func getCommitRiskScoresSlice(collatedScore string) []float64 {
	scoreStrings := strings.Split(collatedScore, ";")
	var scores []float64

	for _, scoreString := range scoreStrings {
		scoreString = strings.TrimSpace(scoreString)
		if scoreString == "" {
			continue // skip empty parts (like the one after trailing ';')
		}
		score, err := strconv.ParseFloat(scoreString, 64)
		if err != nil {
			fmt.Printf("error parsing '%s': %v\n", scoreString, err)
			continue
		}
		scores = append(scores, score)
	}

	return scores
}

func assignCommitRiskWeight(score float64) float64 {
	if score >= 10 {
		return 1.5 // High-risk weight
	} else if score >= 7.5 {
		return 1.2 // Moderate-risk weight
	} else if score >= 4.0 {
		return 1.0 // Normal weight
	} else {
		return 0.8 // Low severity weight
	}
}

// computeWACR calculates the Weighted Average Commit Risk (WACR) for an author.
func computeWACR(commitScores []float64) float64 {
	var weightedSum, totalWeight float64
	for _, score := range commitScores {
		weight := assignCommitRiskWeight(score)
		weightedSum += score * weight
		totalWeight += weight
	}
	if totalWeight == 0 {
		return 0
	}
	return weightedSum / totalWeight
}

// computeRiskScore calculates the overall risk score of an author based on commits.
func GetAuthorRiskScore(collatedScore string) string {
	commitScores := getCommitRiskScoresSlice(collatedScore)
	N := float64(len(commitScores))
	if N == 0 {
		return "0"
	}

	WACR := computeWACR(commitScores)

	// Count High-Risk Commits (≥ 10) and Moderate-Risk Commits (7.5–10)
	var HRC, MRC int
	for _, score := range commitScores {
		if score >= 10 {
			HRC++
		} else if score >= 7.5 {
			MRC++
		}
	}

	HRP := float64(HRC) / N
	MRP := float64(MRC) / N

	// Apply scaling adjustments for high-risk and moderate-risk impact.
	riskScore := WACR * (1 + config.HighRiskCommitConstant*HRP + config.ModerateRiskCommitConstant*MRP)
	riskScoreString := strconv.FormatFloat(riskScore, 'f', 2, 64)
	return riskScoreString
}
