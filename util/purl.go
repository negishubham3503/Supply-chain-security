package util

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-github/v72/github"
	"golang.org/x/oauth2"
)

var supportedFiles = []string{
	"go.sum",
	"package-lock.json",
	"requirements.txt",
}

func ParseGitHubURL(repoURL string) (owner, repo string, err error) {
	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return "", "", err
	}

	parts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid GitHub repo URL: %s", repoURL)
	}

	return parts[0], strings.TrimSuffix(parts[1], ".git"), nil
}

func fileExists(ctx context.Context, client *github.Client, owner, repo, file string) bool {
	_, _, resp, err := client.Repositories.GetContents(ctx, owner, repo, file, &github.RepositoryContentGetOptions{})
	return err == nil && resp.StatusCode == 200
}

func GetLockFileCommits(ctx context.Context, client *github.Client, owner, repo, path string) ([]*github.RepositoryCommit, error) {
	opts := &github.CommitsListOptions{
		Path: path,
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	var allCommits []*github.RepositoryCommit
	for {
		commits, resp, err := client.Repositories.ListCommits(ctx, owner, repo, opts)
		if err != nil {
			return nil, err
		}

		allCommits = append(allCommits, commits...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allCommits, nil
}

func FetchFileAtCommit(ctx context.Context, client *github.Client, owner, repo, path, sha string) (string, error) {
	fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repo, path, &github.RepositoryContentGetOptions{Ref: sha})
	if err != nil || fileContent == nil {
		return "", err
	}

	fmt.Printf("Fetching Commit Contents...\n")

	content, err := fileContent.GetContent()
	if err != nil {
		return "", err
	}

	return content, nil
}

func extractGoPackages(content string) []string {
	var pkgs []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			module := fields[0]
			version := fields[1]
			version = strings.TrimSuffix(version, "/go.mod")
			purl := fmt.Sprintf("pkg:golang/%s@%s", module, version)
			if _, ok := seen[purl]; !ok {
				seen[purl] = struct{}{}
				pkgs = append(pkgs, purl)
			}
		}
	}
	return pkgs
}

func extractNpmPackages(content string) []string {
	var pkgs []string
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(content), &data); err == nil {

		if packages, ok := data["packages"].(map[string]interface{}); ok {
			for pathKey, val := range packages {
				if pathKey == "" || pathKey == "node_modules" {
					continue // skip root entry
				}
				if meta, ok := val.(map[string]interface{}); ok {
					name := strings.TrimPrefix(pathKey, "node_modules/")
					version, _ := meta["version"].(string)
					if name != "" && version != "" {
						purl := fmt.Sprintf("pkg:npm/%s@%s", name, version)
						pkgs = append(pkgs, purl)
					}
				}
			}
		}
	}

	return pkgs
}

func extractPythonPackages(content string) []string {

	var pkgs []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "==")
		if len(parts) == 2 {
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			version := strings.TrimSpace(parts[1])
			purl := fmt.Sprintf("pkg:pypi/%s@%s", name, version)
			pkgs = append(pkgs, purl)
		}
	}
	return pkgs

}

func ExtractPackages(filename, content string) []string {
	var pkgs []string

	fmt.Printf("Processing Packages Found...\n")

	switch filename {
	case "go.sum":
		pkgs = extractGoPackages(content)

	case "requirements.txt":
		pkgs = extractPythonPackages(content)

	case "package-lock.json":
		pkgs = extractNpmPackages(content)
	}

	return pkgs
}

func NewGitHubClient(ctx context.Context, token string) *github.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

func FindLockfile(ctx context.Context, client *github.Client, owner, repo string, jsonFlag bool) (string, error) {
	for _, file := range supportedFiles {
		if !fileExists(ctx, client, owner, repo, file) {
			if !jsonFlag {
				fmt.Printf("Skipping %s: not found\n", file)
			} else {
				continue
			}
		} else {
			return file, nil
		}
	}
	return "", errors.New("lockfile not supported or does not exist")
}
