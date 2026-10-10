package aws

import (
	"strings"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
)

// CredentialSources returns a bounded description of SDK provider metadata.
// It never retrieves credentials, inspects their contents, or prints a provider
// object, profile/path, endpoint, or arbitrary Credentials.Source string. Unknown,
// absent or oversized metadata returns unavailable without changing authentication.
// The labels describe reported sources, not credential-search or refresh history.
func CredentialSources(cfg sdk.Config) string {
	provider, ok := cfg.Credentials.(sdk.CredentialProviderSource)
	if !ok {
		return "unavailable"
	}
	sources := provider.ProviderSources()
	if len(sources) == 0 || len(sources) > 32 {
		return "unavailable"
	}
	labels := make([]string, 0, len(sources))
	seen := make(map[string]bool, len(sources))
	for _, source := range sources {
		label := credentialSourceLabel(source)
		if label == "" {
			return "unavailable"
		}
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
	}
	return strings.Join(labels, ", ")
}

func credentialSourceLabel(source sdk.CredentialSource) string {
	switch source {
	case sdk.CredentialSourceCode:
		return "in-process/static"
	case sdk.CredentialSourceEnvVars:
		return "environment"
	case sdk.CredentialSourceEnvVarsSTSWebIDToken, sdk.CredentialSourceProfileSTSWebIDToken, sdk.CredentialSourceSTSAssumeRoleWebID:
		return "web identity"
	case sdk.CredentialSourceSTSAssumeRole:
		return "STS AssumeRole"
	case sdk.CredentialSourceSTSAssumeRoleSaml:
		return "STS SAML"
	case sdk.CredentialSourceSTSFederationToken:
		return "STS federation token"
	case sdk.CredentialSourceSTSSessionToken:
		return "STS session token"
	case sdk.CredentialSourceProfile:
		return "shared profile"
	case sdk.CredentialSourceProfileSourceProfile:
		return "source profile"
	case sdk.CredentialSourceProfileNamedProvider:
		return "profile credential source"
	case sdk.CredentialSourceProfileSSO, sdk.CredentialSourceSSO:
		return "IAM Identity Center"
	case sdk.CredentialSourceProfileSSOLegacy, sdk.CredentialSourceSSOLegacy:
		return "IAM Identity Center (legacy)"
	case sdk.CredentialSourceProfileProcess, sdk.CredentialSourceProcess:
		return "credential process"
	case sdk.CredentialSourceHTTP:
		// This metadata is also used for generic HTTP providers, not just ECS.
		return "HTTP credentials endpoint"
	case sdk.CredentialSourceIMDS:
		return "EC2 instance metadata"
	case sdk.CredentialSourceProfileLogin, sdk.CredentialSourceLogin:
		return "login cache"
	}
	return ""
}
