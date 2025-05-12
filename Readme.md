# Supply chain security

## Updated instructions on how to run the project

1. Define a .env file in the repo and add a Github Personal Access Token
> GITHUB_ACCESS_TOKEN = _____________

2. Install the required dependencies and compile the repo
> go get
> go build -o scs

3. Run the executable using the command and pass it the GITHUB_URL you want to analyze
> ./scs repo --url GITHUB_URL
