# Supply chain security
This is a command-line tool which can analyze public Github repositories and scan their open-source dependencies to determine risk related to commits and commit authors.

# Usage: Commands
There are two core commands available - `risk` and `sbom`. Both of these commands require specifying the `--url` flag.

### 1. risk
This command is used to evaluate risk related to commits and commits authors in the Github repository provided. Atleast one of the `--commit` or `--author` flags must be specified or both can be specified. 

#### risk Flags
`--commit` : Analyze commit risk. **Important!** - This must be executed before author risk can be evaluated.

`--author`: Analyze commit author risk 

### 2. sbom
This command is used to generate a SBOM of the Github repository provided. If you do not specify any flags then this returns an sbom of the repository. Can be additionally used with the `--version` or `--vulnerability` flags, or both at once.

#### sbom Flags
`--version` : Check for outdated dependencies using SBOM

`--vulnerability`: Check for known vulnerable dependencies using SBOM

### 3. Other Flags
Some additional commands are also provided to provide output as a json, or get help on the usage of the command

`--json`: Provide output as json 

`--help`: Get help on usage

#### Example usage
You can use this command to get the commit risk, commit author risk, all as a json file

```bash
./supply-chain-security risk --commit --author --json --url https://github.com/githubuser/exampleApp
```

You can use this command to just scan your repository for outdated packages

```bash
./supply-chain-security sbom --version --url https://github.com/githubuser/exampleApp
```


## Instructions on how to run the project

0. Clone the directory into your local, make sure you are connected to VU network

```bash 
git clone git@git.mif.vu.lt:micac/2025/supply-chain-security-go.git
```

1. Make a Github Personal Access Token
    - Go to Settings > Developer Settings > Personal Access Tokens
    - Select Tokens (classic) and click Generate new token
    - Select the following scopes -> repo, write:packages, and user
    - Click generate token and Copy the generated token

2. Define a .env file in the repo and add a Github Personal Access Token
`GITHUB_ACCESS_TOKEN = _____________`

3. Install the required dependencies and compile the repo
```bash
go get
go build -o supply-chain-security
```

4. Run the executable using the commands and pass it the GITHUB_URL you want to analyze with different commands and flags

    





