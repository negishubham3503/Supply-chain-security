package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-github/v72/github"
	"github.com/hashicorp/go-version"
)

type Purl struct {
	Name          string
	Outdated      bool
	LatestVersion string
}

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
	fmt.Printf("Detecting ecosystem in Repo...\n")
	env, err := detectEcosystemFromLockfile(ctx, client, owner, repo)
	if err != nil {
		panic("Lockfile not supported")
	}
	fmt.Printf("✅ Ecosystem Detected --> %s\n", env)

	fmt.Printf("Getting SBOM of repo...\n")

	sbom, _, err := client.DependencyGraph.GetSBOM(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get SBOM: %w", err)
	}

	fmt.Printf("✅ SBOM found\n")

	// Parse dependencies
	fmt.Printf("Processing Dependencies...\n")

	var purls []string
	for _, pkg := range sbom.GetSBOM().Packages {
		if strings.EqualFold(pkg.GetName(), repo) || strings.Contains(pkg.GetName(), repo) {
			continue
		}
		purl := makePURL(env, pkg.GetName(), pkg.GetVersionInfo())
		purls = append(purls, purl)
	}
	fmt.Printf("✅ Finished Processing Dependencies\n")

	return purls, nil
}

func compareVersions(current, latest string) (bool, string, error) {
	vCurrent, err := version.NewVersion(current)
	if err != nil {
		return false, "", fmt.Errorf("invalid current version: %w", err)
	}

	vLatest, err := version.NewVersion(latest)
	if err != nil {
		return false, "", fmt.Errorf("invalid latest version: %w", err)
	}

	return vCurrent.LessThan(vLatest), latest, nil
}

func checkNpm(name, currentVer string) (bool, string, error) {
	resp, err := http.Get(fmt.Sprintf("https://registry.npmjs.org/%s", name))
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	var data struct {
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false, "", err
	}

	return compareVersions(currentVer, data.DistTags.Latest)
}

func checkPyPI(name, currentVer string) (bool, string, error) {
	resp, err := http.Get(fmt.Sprintf("https://pypi.org/pypi/%s/json", name))
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	var data struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false, "", err
	}

	return compareVersions(currentVer, data.Info.Version)
}

func checkGo(name, currentVer string) (bool, string, error) {
	// Replace slashes in Go module names with URL encoding
	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", name)
	resp, err := http.Get(url)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	var data struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false, "", err
	}

	return compareVersions(currentVer, data.Version)
}

func CompareLatestVersion(purl string) (outdated bool, latestVersion string, err error) {
	if !strings.HasPrefix(purl, "pkg:") {
		return false, "", errors.New("invalid PURL format")
	}

	purl = strings.TrimPrefix(purl, "pkg:")

	slashIndex := strings.Index(purl, "/")
	if slashIndex == -1 {
		return false, "", errors.New("invalid PURL structure")
	}

	ecosystem := purl[:slashIndex]
	full := purl[slashIndex+1:]

	atIndex := strings.LastIndex(full, "@")
	if atIndex == -1 {
		return false, "", errors.New("missing version in PURL")
	}

	name := full[:atIndex]
	version := full[atIndex+1:]

	switch ecosystem {
	case "npm":
		return checkNpm(name, version)
	case "pypi":
		return checkPyPI(name, version)
	case "golang":
		return checkGo(name, version)
	default:
		return false, "", fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}
