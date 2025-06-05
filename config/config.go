package config

const (
	GithubApiBaseUrl = "https://api.github.com"
	OSVApiBaseUrl    = "https://api.osv.dev/v1"
	// Tuning constant for high-risk commit and scaling factor
	RiskScoreConstant = 0.36
	HighRiskThreshold = 7.0

	// Tuning constants for high-risk and moderate-risk influence
	HighRiskCommitConstant     = 0.8 // Adjusts the impact of high-risk commits
	ModerateRiskCommitConstant = 0.4 // Adjusts the impact of moderate-risk commits

)
