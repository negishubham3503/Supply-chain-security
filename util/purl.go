package util

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/google/go-github/github"
)

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

func GetDefaultBranch(ctx context.Context, client *github.Client, owner, repo string) (string, error) {
	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", err
	}
	return repository.GetDefaultBranch(), nil
}

func FileExists(ctx context.Context, client *github.Client, owner, repo, branch, file string) bool {
	_, _, resp, err := client.Repositories.GetContents(ctx, owner, repo, file, &github.RepositoryContentGetOptions{Ref: branch})
	return err == nil && resp.StatusCode == 200
}

func ListCommitsTouchingFile(ctx context.Context, client *github.Client, owner, repo, branch, path string) ([]*github.RepositoryCommit, error) {
	opts := &github.CommitsListOptions{
		SHA:  branch,
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

	// newest first, reverse to compare oldest to newest
	sort.Slice(allCommits, func(i, j int) bool {
		return allCommits[i].GetCommit().GetCommitter().GetDate().Before(
			allCommits[j].GetCommit().GetCommitter().GetDate())
	})

	return allCommits, nil
}

func FetchFileAtCommit(ctx context.Context, client *github.Client, owner, repo, path, sha string) (string, error) {
	fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repo, path, &github.RepositoryContentGetOptions{Ref: sha})
	if err != nil || fileContent == nil {
		return "", err
	}

	content, err := fileContent.GetContent()
	if err != nil {
		return "", err
	}

	return content, nil
}

func ExtractPackages(filename, content string) []string {
	var pkgs []string

	switch filename {
	case "go.sum":
		seen := make(map[string]struct{})
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				module := fields[0]
				version := fields[1]
				// strip /go.mod if present
				if strings.HasSuffix(version, "/go.mod") {
					version = strings.TrimSuffix(version, "/go.mod")
				}
				purl := fmt.Sprintf("pkg:golang/%s@%s", module, version)
				if _, ok := seen[purl]; !ok {
					seen[purl] = struct{}{}
					pkgs = append(pkgs, purl)
				}
			}
		}

	case "requirements.txt":
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

	case "package-lock.json":
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(content), &data); err == nil {

			// Try v2+ format (npm 7+)
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

	}

	return pkgs
}

func DiffPkgLists(oldPkgs, newPkgs []string) []string {
	oldMap := make(map[string]struct{})
	for _, p := range oldPkgs {
		oldMap[p] = struct{}{}
	}

	var added []string
	for _, p := range newPkgs {
		if _, exists := oldMap[p]; !exists {
			added = append(added, p)
		}
	}
	return added
}
