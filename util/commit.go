package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"supply-chain-security/config"
	"supply-chain-security/types"
	"time"
)

func ParsePURL(purl string) (types.Package, error) {
	parts := strings.Split(purl, "@")
	if len(parts) != 2 {
		return types.Package{}, fmt.Errorf("invalid PURL format")
	}

	version := parts[1]
	nameParts := strings.Split(parts[0], "/")

	if len(nameParts) < 2 {
		return types.Package{}, fmt.Errorf("invalid package format")
	}

	ecosystemParts := strings.Split(nameParts[0], ":")
	if len(ecosystemParts) != 2 {
		return types.Package{}, fmt.Errorf("invalid ecosystem format")
	}

	ecosystem := ecosystemParts[1] // Extract ecosystem (e.g., "pypi")
	name := nameParts[len(nameParts)-1]

	pkg := types.Package{Name: name, Version: version, Ecosystem: ecosystem}

	return pkg, nil
}

type osvQueryRequest struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

// osvQueryResponse represents the structure of the OSV API response
type osvQueryResponse struct {
	Vulns         []map[string]interface{} `json:"vulns"`
	NextPageToken string                   `json:"next_page_token"`
}

func GetOSVDataByDependencyPurl(purlStr string) ([]map[string]interface{}, error) {
	parsed, err := ParsePURL(purlStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing PURL: %w", err)
	}

	apiURL := config.OSVApiBaseUrl + "/query"
	var results []map[string]interface{}
	pageToken := ""

	for {
		// Build request payload
		reqBody := osvQueryRequest{
			Version:   parsed.Version,
			PageToken: pageToken,
		}
		reqBody.Package.Ecosystem = parsed.Ecosystem
		reqBody.Package.Name = parsed.Name

		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("error marshaling request: %w", err)
		}

		// Execute HTTP POST
		resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, fmt.Errorf("error posting to OSV: %w", err)
		}
		defer resp.Body.Close()

		// Check HTTP status
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("OSV API error: %s, body: %s", resp.Status, body)
		}

		// Decode JSON response
		var osvResp osvQueryResponse
		err = json.NewDecoder(resp.Body).Decode(&osvResp)
		if err != nil {
			return nil, fmt.Errorf("error decoding OSV response: %w", err)
		}

		results = append(results, osvResp.Vulns...)

		// Check if more pages exist
		if osvResp.NextPageToken == "" {
			break
		}
		pageToken = osvResp.NextPageToken
	}

	return results, nil
}

func GetAllCommitSHAByRepo(repo types.Repo) []string {
	var shaValues []string
	page := 1

	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=100&page=%d", baseUrl, repo.Owner, repo.Name, page)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching commits for the provided repo: ", repo.Name, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var rawCommits []map[string]interface{}
	err = json.Unmarshal(body, &rawCommits)
	if err != nil {
		panic(err)
	}

	for _, commit := range rawCommits {
		if sha, ok := commit["sha"].(string); ok {
			shaValues = append(shaValues, sha)
		}
	}

	return shaValues
}

func GetAllCommitChangesBySHA(repo types.Repo, sha string) types.Commit {
	var commit types.Commit
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", baseUrl, repo.Owner, repo.Name, sha)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching commit for the provided sha: ", sha, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &commit)
	return commit
}

func GetAllCommitsChangesByRepo(repo types.Repo) []types.Commit {
	var allCommits []types.Commit
	allCommitSHAValues := GetAllCommitSHAByRepo(repo)

	for _, sha := range allCommitSHAValues {
		commit := GetAllCommitChangesBySHA(repo, sha)
		allCommits = append(allCommits, commit)
	}

	return allCommits
}

func GetVulnerabilityIntroducerCommit(sha string) ([]string, error) {
	apiURL := config.OSVApiBaseUrl + "/query"

	// Create payload with single commit
	payload := map[string]string{"commit": sha}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return []string{}, err
	}

	// Make POST request
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return []string{}, err
	}
	defer resp.Body.Close()

	// Decode response JSON
	var osvResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&osvResponse)
	if err != nil {
		return []string{}, err
	}

	var vulnerableCommitSha []string
	// Extract vulnerabilities
	if vulns, ok := osvResponse["vulns"].([]interface{}); ok {
		for _, vulnData := range vulns {
			vuln, _ := vulnData.(map[string]interface{})
			fmt.Println("Vulnerability ID:", vuln["id"])
			fmt.Println("Details:", vuln["details"])

			// Extract affected repositories
			if affectedArr, ok := vuln["affected"].([]interface{}); ok {
				for _, affectedData := range affectedArr {
					affected, _ := affectedData.(map[string]interface{})
					if rangesArr, ok := affected["ranges"].([]interface{}); ok {
						for _, rangeData := range rangesArr {
							rng, _ := rangeData.(map[string]interface{})
							if rng["type"] == "GIT" { // Ensure it's a repo-specific vulnerability
								fmt.Println("Repository:", rng["repo"])
								if eventsArr, ok := rng["events"].([]interface{}); ok {
									for _, eventData := range eventsArr {
										event, _ := eventData.(map[string]interface{})
										if introduced, exists := event["introduced"]; exists {
											if introducedStr, ok := introduced.(string); ok && introducedStr != "0" {
												vulnerableCommitSha = append(vulnerableCommitSha, introducedStr) // Append only if introduced is NOT "0"
											} else {
												fmt.Println("Skipping introduced:", introducedStr)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return vulnerableCommitSha, nil
}

func GetAllVulnerableCommitsinOSVByRepo(repo types.Repo) []types.Commit {
	allCommitSHA := GetAllCommitSHAByRepo(repo)
	var allVulnerableCommitSha []string

	var allVulnerableCommits []types.Commit

	for _, commitSha := range allCommitSHA {
		vulnerablesha, err := GetVulnerabilityIntroducerCommit(commitSha)
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			allVulnerableCommitSha = append(allVulnerableCommitSha, vulnerablesha...)
		}
	}

	seen := make(map[string]bool) // Map to track seen elements
	var allUniqueVulnerableSha []string

	for _, sha := range allVulnerableCommitSha {
		if !seen[sha] { // Only add if not seen before
			seen[sha] = true
			allUniqueVulnerableSha = append(allUniqueVulnerableSha, sha)
		}
	}

	for _, commitSha := range allUniqueVulnerableSha {
		vulnerableCommit := GetAllCommitChangesBySHA(repo, commitSha)
		allVulnerableCommits = append(allVulnerableCommits, vulnerableCommit)
	}

	return allVulnerableCommits
}

func EvaluateRiskByCommit(commit types.Commit, purls []string) (types.CommitRisk, error) {
	var commitRisk types.CommitRisk
	commitRisk.Score = ""
	commitRisk.Commit = commit
	commitTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", commit.Date)
	if err != nil {
		fmt.Println("Error parsing date:", err)
		return types.CommitRisk{}, err
	}

	for _, purl := range purls {
		osvData, err := GetOSVDataByDependencyPurl(purl)
		if err != nil {
			return types.CommitRisk{}, err
		}

		if len(osvData) == 0 {
			fmt.Printf("No vulnerabilities found for %s\n", purl)
			continue
		}

		for _, vuln := range osvData {
			// Parse publish time
			publishedStr, ok := vuln["published"].(string)
			if !ok {
				fmt.Println("Missing or invalid 'published' field")
				continue
			}
			vulnPublishTime, err := time.Parse(time.RFC3339, publishedStr)
			if err != nil {
				fmt.Printf("Error parsing publish time: %v\n", err)
				continue
			}

			// Compare to commit time
			if commitTime.After(vulnPublishTime) {
				// Severity is relevant since result is already filtered by PURL
				if severity, ok := vuln["severity"].([]interface{}); ok && len(severity) > 0 {
					for _, s := range severity {
						if sevMap, ok := s.(map[string]interface{}); ok {
							if sevVal, ok := sevMap["score"].(string); ok {
								if commitRisk.Score == "" {
									commitRisk.Score = sevVal
								} else {
									commitRisk.Score += ";" + sevVal
								}
							}
						}
					}
				}
			}
		}

	}

	return commitRisk, nil
}
