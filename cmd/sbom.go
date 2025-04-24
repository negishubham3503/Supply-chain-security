package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type GitHubSBOM struct {
	Sbom struct {
		SpdxVersion       string `json:"spdxVersion"`
		DataLicense       string `json:"dataLicense"`
		Spdxid            string `json:"SPDXID"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		CreationInfo      struct {
			Creators []string  `json:"creators"`
			Created  time.Time `json:"created"`
		} `json:"creationInfo"`
		Packages []struct {
			Name             string `json:"name"`
			Spdxid           string `json:"SPDXID"`
			VersionInfo      string `json:"versionInfo"`
			DownloadLocation string `json:"downloadLocation"`
			FilesAnalyzed    bool   `json:"filesAnalyzed"`
			LicenseConcluded string `json:"licenseConcluded,omitempty"`
			CopyrightText    string `json:"copyrightText,omitempty"`
			ExternalRefs     []struct {
				ReferenceCategory string `json:"referenceCategory"`
				ReferenceType     string `json:"referenceType"`
				ReferenceLocator  string `json:"referenceLocator"`
			} `json:"externalRefs"`
			LicenseDeclared string `json:"licenseDeclared,omitempty"`
		} `json:"packages"`
		Relationships []struct {
			SpdxElementID      string `json:"spdxElementId"`
			RelatedSpdxElement string `json:"relatedSpdxElement"`
			RelationshipType   string `json:"relationshipType"`
		} `json:"relationships"`
	} `json:"sbom"`
}

var sbomCmd = &cobra.Command{
	Use:  "sbom",
	Long: "Enter your repository URL to retrieve SPDX format SBOM",
	Run: func(cmd *cobra.Command, args []string) {

		parsedUrl, err := url.Parse(args[0])
		if err != nil {
			fmt.Println("Error parsing the repository URL that you entered")
			return
		}
		sbomUrl := baseUrl + parsedUrl.Path + "/dependency-graph/sbom"

		resp, err := http.Get(sbomUrl)
		if err != nil {
			fmt.Println("There is some issue while fetching details from the repository URL")
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("There is some issue while fetching details from the repository URL")
			return
		}

		sbom := GitHubSBOM{}
		json.Unmarshal(body, &sbom)

		prettified, err := json.MarshalIndent(sbom, "", "\t")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(prettified))

		err = os.WriteFile("bom.json", prettified, 0644)
		if err != nil {
			fmt.Println("There is some issue while saving response to file")
			return
		}

	},
}

func init() {
	rootCmd.AddCommand(sbomCmd)
}
