package cmd

import (
	"context"
	"fmt"
	"os"
	"supply-chain-security/util"

	"github.com/joho/godotenv"

	"github.com/spf13/cobra"
)

var (
	versionFlag       bool
	vulnerabilityFlag bool
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Get SBOM risk analysis from repo",
	Long:  "Get a detailed risk analysis of direct and transitive dependencies being used currently in your repository.",
	Run: func(cmd *cobra.Command, args []string) {

		if repoURL == "" {
			fmt.Println("Error: --url flag is required")
			return
		}

		fmt.Printf("Starting Authenticated Github Client...\n")

		ctx := context.Background()
		_ = godotenv.Load()

		token := os.Getenv("GITHUB_ACCESS_TOKEN")
		if token == "" {
			panic("Github Token Not set")
		}

		client := util.NewGitHubClient(ctx, token)
		fmt.Printf("✅ Github Client Started\n")

		owner, repo, err := util.ParseGitHubURL(repoURL)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Processing Dependencies...\n")

		purls, err := util.FetchDependenciesViaSBOM(ctx, client, owner, repo)
		if err != nil {
			panic("SBOM Dependency didnt work")
		}

		fmt.Printf("✅ Dependencies Processed\n")

		if versionFlag {
			fmt.Printf("Analyzing Dependency Versions...\n")

			for _, purl := range purls {
				outdated, latestVersion, err := util.CompareLatestVersion(purl)
				if err != nil {
					panic(err)
				}
				if outdated {
					fmt.Printf("A Newer version of %s is available --> %s\n", purl, latestVersion)
				}
			}

			fmt.Printf("✅ Dependency Version Analysis Complete\n")
		}

		if vulnerabilityFlag {
			fmt.Printf("Scanning Dependencies for Vulnerabilities\n")
			for _, purl := range purls {
				osvData, err := util.GetOSVDataByDependencyPurl(purl)
				if err != nil {
					panic(err)
				}

				if len(osvData) == 0 {
					fmt.Printf("\r\033[2KNo vulnerabilities found for %s", purl)
					continue
				} else {
					fmt.Printf("\r\033[K")
					fmt.Printf("Vunerability Detected for %s\n", purl)
				}
			}

			fmt.Printf("\n✅ Vulnerability Scanning Complete\n")
		}

	},
}

func init() {
	sbomCmd.Flags().StringVarP(&repoURL, "url", "u", "", "GitHub repository URL (required)")
	sbomCmd.MarkFlagRequired("url")
	sbomCmd.Flags().BoolVarP(&versionFlag, "version", "e", false, "Check if your packages are updated")
	sbomCmd.Flags().BoolVarP(&vulnerabilityFlag, "vulnerability", "v", false, "Find vulnerabilities in current dependencies")

	rootCmd.AddCommand(sbomCmd)
}
