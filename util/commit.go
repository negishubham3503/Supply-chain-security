package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"supply-chain-security/config"
	"supply-chain-security/types"
	"time"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
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

func GetVulnerabilityIntroducerCommitRisk(sha string, allVulnerableCommitsWithRisk []types.VulnerableCommit) ([]types.VulnerableCommit, error) {
	apiURL := config.OSVApiBaseUrl + "/query"

	// Create payload with single commit
	payload := map[string]string{"commit": sha}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return allVulnerableCommitsWithRisk, err
	}

	// Make POST request
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return allVulnerableCommitsWithRisk, err
	}
	defer resp.Body.Close()

	// Decode response JSON
	var osvResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&osvResponse)
	if err != nil {
		return allVulnerableCommitsWithRisk, err
	}

	vulnerableCommits := allVulnerableCommitsWithRisk
	// Extract vulnerabilities
	if vulns, ok := osvResponse["vulns"].([]interface{}); ok {
		for _, vulnData := range vulns {
			vuln, _ := vulnData.(map[string]interface{})
			fmt.Println("Vulnerability ID:", vuln["id"])
			fmt.Println("Details:", vuln["details"])

			vulnId := vuln["id"].(string)

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
												if !contains(vulnerableCommits, introducedStr, vulnId) {
													var vulnerableCommit types.VulnerableCommit
													vulnerableCommit.CommitSha = introducedStr
													vulnerableCommit.VulnerabilityId = vulnId
													if severity, ok := vuln["severity"].([]interface{}); ok && len(severity) > 0 {
														for _, s := range severity {
															if sevMap, ok := s.(map[string]interface{}); ok {
																if sevVal, ok := sevMap["score"].(string); ok {
																	vulnerableCommit.RiskScore = sevVal
																}
															}
														}
													}
													vulnerableCommits = append(vulnerableCommits, vulnerableCommit)
												}
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

	return vulnerableCommits, nil
}

func contains(allVulnerableCommit []types.VulnerableCommit, commitSha string, vulnId string) bool {
	for _, vulnCommit := range allVulnerableCommit {
		if vulnCommit.CommitSha == commitSha && vulnCommit.VulnerabilityId == vulnId {
			return true
		}
	}
	return false
}

func GetAllVulnerableCommitsinOSVByRepo(repo types.Repo) []types.CommitRisk {
	allCommitSHA := GetAllCommitSHAByRepo(repo)
	var allVulnerableCommitsWithRisk []types.VulnerableCommit

	var allVulnerableCommitRisk []types.CommitRisk

	for _, commitSha := range allCommitSHA {
		fmt.Printf("Commit #%s\n", commitSha)
		vulnerableCommit, err := GetVulnerabilityIntroducerCommitRisk(commitSha, allVulnerableCommitsWithRisk)
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			allVulnerableCommitsWithRisk = append(allVulnerableCommitsWithRisk, vulnerableCommit...)
		}
	}

	groupedByCommitSha := make(map[string][]types.VulnerableCommit)

	for _, vulnerableCommit := range allVulnerableCommitsWithRisk {
		groupedByCommitSha[vulnerableCommit.CommitSha] = append(groupedByCommitSha[vulnerableCommit.CommitSha], vulnerableCommit)
	}

	for commitSha, vulnerabilityIdWithRisk := range groupedByCommitSha {
		var commitRisk types.CommitRisk
		commitRisk.Commit = GetAllCommitChangesBySHA(repo, commitSha)
		combinedRiskScore := ""
		for _, vulnIdAndRiskScore := range vulnerabilityIdWithRisk {
			combinedRiskScore += vulnIdAndRiskScore.RiskScore
		}
		commitRisk.Score = combinedRiskScore
		allVulnerableCommitRisk = append(allVulnerableCommitRisk, commitRisk)
	}

	return allVulnerableCommitRisk
}

func FormCompleteCombinedCommitRisksByRepo(repo types.Repo, allRepoCommitRisk []types.CommitRisk) []types.CommitRisk {
	allCodeLevelVulnerableCommitRisks := GetAllVulnerableCommitsinOSVByRepo(repo)
	allRepoCommitsByCombinedRisk := allRepoCommitRisk
	for _, codeLevelCommitRisk := range allCodeLevelVulnerableCommitRisks {
		for _, dependencyCommitRisk := range allRepoCommitsByCombinedRisk {
			if codeLevelCommitRisk.Commit == dependencyCommitRisk.Commit {
				dependencyCommitRisk.Score = dependencyCommitRisk.Score + codeLevelCommitRisk.Score + ";"
			}
		}
	}

	return allRepoCommitsByCombinedRisk
}

func EvaluateRiskByCommit(commit types.Commit, purls []string, jsonFlag bool) (types.CommitRisk, error) {
	var commitRisk types.CommitRisk
	commitRisk.Score = ""
	commitRisk.Commit = commit
	commitTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", commit.Date)
	if err != nil {
		fmt.Println("Error parsing date:", err)
		return types.CommitRisk{}, err
	}

	fmt.Printf("Starting Risk Analysis of Packages in Commit...")

	for _, purl := range purls {
		osvData, err := GetOSVDataByDependencyPurl(purl)
		if err != nil {
			return types.CommitRisk{}, err
		}
		if !jsonFlag {

			if len(osvData) == 0 {
				fmt.Printf("\r\033[2KNo vulnerabilities found for %s", purl)
				continue
			} else {
				fmt.Printf("\r\033[K")
				fmt.Printf("Vunerability Detected for %s\n", purl)
			}
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
				if severity, ok := vuln["severity"].([]any); ok && len(severity) > 0 {
					sevVal := severity[len(severity)-1].(map[string]any)
					commitRisk.Score += sevVal["score"].(string)
					// for _, s := range severity {
					// 	if sevMap, ok := s.(map[string]interface{}); ok {
					// 		if sevVal, ok := sevMap["score"].(string); ok {
					// 			if commitRisk.Score == "" {
					// 				commitRisk.Score = sevVal
					// 			} else {
					// 				commitRisk.Score += ";" + sevVal
					// 			}
					// 		}
					// 	}
					// }
				}
			}
		}

	}
	fmt.Printf("\n✅ Risk Analysis of Packages in Commit Finished\n")

	return commitRisk, nil
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
