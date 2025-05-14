package util

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v72/github"
)

func makePURL(pkgType, name, version string) string {

	pkgType = strings.ToLower(strings.TrimSpace(pkgType))
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)

	return fmt.Sprintf("pkg:%s/%s@%s", pkgType, name, version)
}

func detectEcosystemFromLockfile(ctx context.Context, client *github.Client, owner, repo string) (string, error) {
	lockfiles := map[string]string{
		"package-lock.json": "npm",
		"go.sum":            "golang",
		"requirements.txt":  "pypi",
	}

	for file, ecosystem := range lockfiles {
		_, _, resp, err := client.Repositories.GetContents(ctx, owner, repo, file, nil)
		if err == nil && resp.StatusCode == 200 {
			return ecosystem, nil
		}
	}

	return "", fmt.Errorf("no known lockfile found in repository %s/%s", owner, repo)
}

// FetchDependenciesViaSBOM fetches the SBOM and returns a slice of dependency PURLs.
func FetchDependenciesViaSBOM(ctx context.Context, client *github.Client, owner, repo string) ([]string, error) {

	// Fetch SBOM from GitHub
	env, err := detectEcosystemFromLockfile(ctx, client, owner, repo)
	if err != nil {
		panic("Lockfile not supported")
	}

	sbom, _, err := client.DependencyGraph.GetSBOM(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get SBOM: %w", err)
	}

	// Parse dependencies
	var purls []string
	for _, pkg := range sbom.GetSBOM().Packages {
		purl := makePURL(env, pkg.GetName(), pkg.GetVersionInfo())
		purls = append(purls, purl)
	}

	return purls, nil
}
