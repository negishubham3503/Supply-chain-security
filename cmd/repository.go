package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
)

const baseUrl = "https://api.github.com/repos"

var repositoryCmd = &cobra.Command{
	Use:  "repository",
	Long: "Enter your repository URL to perform compostion analysis",
	Run: func(cmd *cobra.Command, args []string) {
		parsedUrl, err := url.Parse(args[0])
		if err != nil {
			fmt.Println("Error parsing the repository URL that you entered")
			return
		}
		repoUrl := baseUrl + parsedUrl.Path
		resp, err := http.Get(repoUrl)
		if err != nil {
			fmt.Println("There is some isse while fetching details from the repository URL")
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("There is some isse while fetching details from the repository URL")
			return
		}
		fmt.Print(string(body))
	},
}

func init() {
	rootCmd.AddCommand(repositoryCmd)
}
