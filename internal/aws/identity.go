package aws

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"ssmh/internal/logging"
)

// IdentityAPI is the authenticated, read-only caller-identity boundary.
type IdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Identity contains validated non-secret caller metadata, never credentials or
// the STS UserId field. It does not prove authorization to create an SSM session.
type Identity struct{ account, principal string }

// ErrIdentityDenied classifies an explicit STS metadata-access denial without
// retaining raw errors. It must never stand for expired/invalid credentials,
// malformed identity data, TLS failures or cancellation.
var ErrIdentityDenied = errors.New("AWS caller identity metadata access denied")

// Account returns the validated twelve-digit AWS account ID.
func (i Identity) Account() string { return i.account }

// ARN returns the validated IAM/STS principal ARN.
func (i Identity) ARN() string { return i.principal }

var identityAccount = regexp.MustCompile(`^[0-9]{12}$`)
var identityPartition = regexp.MustCompile(`^aws(?:-[a-z0-9-]+)?$`)
var identityResource = regexp.MustCompile(`^[\x21-\x7e]+$`)
var identityName = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)

// ReadIdentity calls STS using the caller's selected client and identity. It
// returns no partial identity and never falls back to another credential source.
func ReadIdentity(ctx context.Context, client IdentityAPI) (Identity, error) {
	if client == nil {
		return Identity{}, errors.New("AWS identity client is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	response, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		var api smithy.APIError
		if errors.As(err, &api) && (api.ErrorCode() == "AccessDenied" || api.ErrorCode() == "AccessDeniedException") {
			return Identity{}, errors.Join(ctx.Err(), ErrIdentityDenied, logging.Failure("read AWS caller identity", err))
		}
		return Identity{}, errors.Join(ctx.Err(), logging.Failure("read AWS caller identity", err))
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	invalid := errors.New("STS returned invalid caller identity metadata")
	if response == nil {
		return Identity{}, invalid
	}
	account, principal := aws.ToString(response.Account), aws.ToString(response.Arn)
	if !identityAccount.MatchString(account) || len(principal) > 2048 {
		return Identity{}, invalid
	}
	a, err := arn.Parse(principal)
	if err != nil || !identityPartition.MatchString(a.Partition) || a.AccountID != account || a.Region != "" || !identityResource.MatchString(a.Resource) {
		return Identity{}, invalid
	}
	valid := false
	kind, subject, found := strings.Cut(a.Resource, "/")
	switch a.Service {
	case "iam":
		valid = a.Resource == "root"
		if found && (kind == "user" || kind == "role") {
			lastSlash := strings.LastIndex(subject, "/")
			// IAM paths allow printable ASCII punctuation and repeated slashes.
			// Their leading slash is omitted in the resource after user/role/.
			valid = lastSlash+2 <= 512 && identityName.MatchString(subject[lastSlash+1:])
		}
	case "sts":
		parts := strings.Split(a.Resource, "/")
		valid = len(parts) == 3 && kind == "assumed-role" && identityName.MatchString(parts[1]) && identityName.MatchString(parts[2])
		valid = valid || found && kind == "federated-user" && identityName.MatchString(subject)
	}
	if !valid {
		return Identity{}, invalid
	}
	return Identity{account, principal}, nil
}
