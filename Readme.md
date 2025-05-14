# Supply chain security

## Updated instructions on how to run the project

0. Clone the directory into your local, make sure you are connected to VU network
`git clone git@git.mif.vu.lt:micac/2025/supply-chain-security-go.git`

1. Define a .env file in the repo and add a Github Personal Access Token
`GITHUB_ACCESS_TOKEN = _____________`

2. Install the required dependencies and compile the repo
`go get`
`go build -o supply-chain-security`

3. Run the executable using the commands and pass it the GITHUB_URL you want to analyze with different commands
## Cobra Commands
`./supply-chain-security sbom --url GITHUB_URL`
`./supply-chain-security repo --url GITHUB_URL`

## Cobra Help Commands
`./supply-chain-security sbom --help`
`./supply-chain-security repo --help`
`./supply-chain-security --help`



