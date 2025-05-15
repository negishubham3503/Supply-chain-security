package types

type Repo struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Owner string `json:"owner.login"`
}

type Author struct {
	ID   int    `json:"id"`
	Name string `json:"login"`
}

type File struct {
	Name    string `json:"filename"`
	Changes int    `json:"changes"`
	Patch   string `json:"patch"`
}

type Commit struct {
	Sha     string `json:"sha"`
	Date    string `json:"commit.author.date"`
	Author  Author `json:"author"`
	Message string `json:"commit.message"`
}

type SecurityAdvisory struct {
	Gsa_Id     string `json:"ghsa_id"`
	CVE_Id     string `json:"cve_id"`
	SourceRepo string `json:"source_code_location"`
}

type Package struct {
	Name      string
	Version   string
	Ecosystem string
}

type CommitRisk struct {
	Score  string
	Commit Commit
}

type AuthorRisk struct {
	Score  string
	Author Author
}

type VulnerableCommit struct {
	VulnerabilityId string `json:"id"`
	CommitSha       string
	RiskScore       string
}
