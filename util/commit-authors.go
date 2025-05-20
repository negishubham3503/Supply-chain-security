package util

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"supply-chain-security/config"
	"supply-chain-security/types"

	"github.com/joho/godotenv"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
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

func SaveSlice(allRepoCommitRisks []types.CommitRisk) {
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

func GetRiskRating(riskCVSSVectorCollated string) string {
	var riskScore string

	if riskCVSSVectorCollated == "" {
		return "0"
	} else {
		//var vectorRE = regexp.MustCompile(`CVSS:(?:2\.0|3\.[01]|4\.0)/[A-Z0-9:/.-]+?(?=CVSS:|$)`)
		riskCVSSVectorSlice := strings.Fields(strings.TrimSpace(strings.ReplaceAll(riskCVSSVectorCollated, "CVSS:", " CVSS:")))
		var cvssScoreSlice []float64
		for _, CVSSVector := range riskCVSSVectorSlice {
			cvssScore, _, err := scoreRiskVector(CVSSVector)
			if err != nil {
				continue
			}
			cvssScoreSlice = append(cvssScoreSlice, cvssScore)
			//fmt.Printf("CVSS %s – Base score %.1f – %s\n", ver, cvssScore, CVSSVector)
		}
		riskScore = strconv.FormatFloat(calculateRiskScore(cvssScoreSlice, config.RiskScoreConstant, config.HighRiskThreshold), 'f', 2, 64)
	}
	return riskScore
}

func scoreRiskVector(vec string) (float64, string, error) {
	switch {
	case regexp.MustCompile(`^CVSS:4\.0/`).MatchString(vec):
		m, err := gocvss40.ParseVector(vec)
		if err != nil {
			return 0, "4.0", err
		}
		return m.Score(), "4.0", nil
	case regexp.MustCompile(`^CVSS:2\.0/`).MatchString(vec):
		m, err := gocvss20.ParseVector(vec)
		if err != nil {
			return 0, "2.0", err
		}
		return m.BaseScore(), "2.0", nil
	case regexp.MustCompile(`^CVSS:3\.0/`).MatchString(vec):
		m, err := gocvss30.ParseVector(vec)
		if err != nil {
			return 0, "3.0", err
		}
		return m.BaseScore(), "3.0", nil
	default: // covers 3.0 and 3.1
		m, err := gocvss31.ParseVector(vec)
		if err != nil {
			return 0, "3.1", err
		}
		return m.BaseScore(), "3.1", nil
	}
}

// assignWeight returns a severity-based weight for a given CVSS score.
// The weighting scheme is as follows:
//   - CVSS 9.0–10.0 → Weight: 1.5
//   - CVSS 7.0–8.9  → Weight: 1.2
//   - CVSS 4.0–6.9  → Weight: 1.0
//   - CVSS 1.0–3.9  → Weight: 0.8
func assignWeight(score float64) float64 {
	if score >= 9.0 {
		return 1.5
	} else if score >= 7.0 {
		return 1.2
	} else if score >= 4.0 {
		return 1.0
	} else {
		return 0.8
	}
}

// riskScore computes the composite risk score given a slice of CVSS scores.
// It calculates the weighted average (WAvg) on the fly, counts the total number (N)
// and the high-risk count (HR, scores >= highRiskThreshold), then applies the formula:
// Risk Score = WAvg * ln(1 + N) * [1 + c * (N-1) * (HR/N)]
func calculateRiskScore(scores []float64, c float64, highRiskThreshold float64) float64 {
	N := float64(len(scores))
	if N == 0 {
		return 0
	}

	var weightedSum, totalWeight float64
	HR := 0

	for _, score := range scores {
		weight := assignWeight(score)
		weightedSum += score * weight
		totalWeight += weight
		// Count high-risk vulnerabilities.
		if score >= highRiskThreshold {
			HR++
		}
	}

	// Compute weighted average CVSS.
	WAvg := weightedSum / totalWeight

	// Calculate bonus multiplier.
	// For commits with a single vulnerability, (N-1) equals 0 and the multiplier stays 1.
	bonusMultiplier := 1 + c*(N-1)*(float64(HR)/N)

	// Final risk score calculation with a logarithmic factor.
	return WAvg * math.Log(1+N) * bonusMultiplier
}
