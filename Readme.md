# Supply chain security
This is a command-line tool which can analyze public Github repositories and scan their open-source dependencies to determine risk related to commits and commit authors.

## Usage -- Commands
### 1. risk
This command is used to evaluate risk related to commits and commits authors in the Github repository provided
#### Flags
`--commit` : Analyze commit risk
`--author`: Analyze commit author risk 
`--json`: Provide output as json
`--url`: The github url to scan (required)

### 2. sbom
This command is used to generate a SBOM of the Github repository provided. If you do not specify any flags then this returns an sbom of the repository
#### Flags
`--version` : Check for outdated dependencies using SBOM
`--vulnerability`: Check for known vulnerable dependencies using SBOM
`--json`: Provide output as json
`--url`: The github url to scan (required)

## Instructions on how to run the project

0. Clone the directory into your local, make sure you are connected to VU network
`git clone git@git.mif.vu.lt:micac/2025/supply-chain-security-go.git`

1. Make a Github Personal Access Token
    - Go to Settings > Developer Settings > Personal Access Tokens
    - Select Tokens (classic) and click Generate new token
    - Select the following scopes -> repo, write:packages, and user
    - Click generate token and Copy the generated token

2. Define a .env file in the repo and add a Github Personal Access Token
`GITHUB_ACCESS_TOKEN = _____________`

3. Install the required dependencies and compile the repo
`go get`
`go build -o supply-chain-security`

4. Run the executable using the commands and pass it the GITHUB_URL you want to analyze with different commands and flags

    





