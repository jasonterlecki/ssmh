package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"ssmh/internal/config"
	"ssmh/internal/ssm"
)

type dataKeyAPI interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}

var kmsKeyID = regexp.MustCompile(`^(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$`)
var kmsAlias = regexp.MustCompile(`^alias/[A-Za-z0-9/_-]{1,250}$`)

// keyReference accepts the documented KMS identifiers without resolving a new
// identity or alias. ARN partition/region must match the owned session region.
func keyReference(key, region string) bool {
	return config.KMSKeyReference(key, region)
}

func matchingKeyARN(selected, returned, region string) bool {
	if !keyReference(selected, region) {
		return false
	}
	if !strings.HasPrefix(returned, "arn:") || !keyReference(returned, region) {
		return false
	}
	parts := strings.SplitN(returned, ":", 6)
	if !strings.HasPrefix(parts[5], "key/") {
		return false
	}
	if strings.HasPrefix(selected, "arn:") {
		wanted := strings.SplitN(selected, ":", 6)
		if wanted[4] != parts[4] {
			return false
		}
		if strings.HasPrefix(wanted[5], "key/") {
			return selected == returned
		}
		return true // Signed KMS response resolves the selected alias in its account.
	}
	if kmsKeyID.MatchString(selected) {
		return parts[5] == "key/"+selected
	}
	return kmsAlias.MatchString(selected)
}

// newKMSPreparer retains the selected SDK configuration; never LoadDefaultConfig.
// Connect obtains selectedKey from authenticated shell/command document ownership.
// This private constructor alone does not grant that document capability.
func newKMSPreparer(ctx context.Context, cfg aws.Config, session *ssm.Session, selectedKey string) (kmsKeyPreparer, error) {
	_, _, region, live := session.OwnedContext()
	if ctx == nil || !live || cfg.Region != region || cfg.Credentials == nil || cfg.HTTPClient == nil || cfg.BaseEndpoint != nil || cfg.EndpointResolver != nil || cfg.EndpointResolverWithOptions != nil || !keyReference(selectedKey, region) {
		return nil, errors.New("invalid owned KMS key preparation configuration")
	}
	for _, source := range cfg.ConfigSources {
		if provider, ok := source.(interface {
			GetServiceBaseEndpoint(context.Context, string) (string, bool, error)
		}); ok {
			if _, found, err := provider.GetServiceBaseEndpoint(ctx, "KMS"); err != nil || found {
				return nil, errors.New("custom KMS endpoints are unsupported")
			}
		}
	}
	client := kms.NewFromConfig(cfg, func(o *kms.Options) { o.ClientLogMode = 0 })
	return ownedKeyPreparer(ctx, client, session, selectedKey, region), nil
}

// ownedKeyPreparer's callback is single-owner and one-use, including failures.
// SDK plaintext is cleared on every response path; copied/expanded memory and
// SDK internal buffers are not guaranteed erased. No raw provider error survives.
func ownedKeyPreparer(ctx context.Context, client dataKeyAPI, session *ssm.Session, selectedKey, region string) kmsKeyPreparer {
	used := false
	return func(parameters kmsParameters) (*sessionCipher, []byte, error) {
		invalid := errors.New("KMS session key preparation failed")
		if used {
			return nil, nil, invalid
		}
		used = true
		id, target, ownedRegion, live := session.OwnedContext()
		if ctx.Err() != nil || !live || ownedRegion != region || !keyReference(selectedKey, region) {
			return nil, nil, invalid
		}
		fields := map[string]string{"KMSKeyId": parameters.keyID}
		if parameters.challenge != "" {
			fields["Challenge"] = parameters.challenge
		}
		raw, err := json.Marshal(fields)
		if err != nil {
			return nil, nil, invalid
		}
		if _, err := parseKMSParameters(raw, selectedKey); err != nil {
			return nil, nil, invalid
		}
		contextValues := map[string]string{"aws:ssm:SessionId": id, "aws:ssm:TargetId": target}
		if parameters.challenge != "" {
			contextValues["aws:ssm:RandomChallenge"] = parameters.challenge
		}
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		output, err := client.GenerateDataKey(requestCtx, &kms.GenerateDataKeyInput{KeyId: aws.String(selectedKey), NumberOfBytes: aws.Int32(sessionKeyBytes), EncryptionContext: contextValues})
		if output != nil {
			defer clear(output.Plaintext)
		}
		_, _, _, stillLive := session.OwnedContext()
		if err != nil || requestCtx.Err() != nil || !stillLive || output == nil || len(output.Plaintext) != sessionKeyBytes || len(output.CiphertextBlob) == 0 || len(output.CiphertextBlob) > 6144 || len(output.CiphertextForRecipient) != 0 || !matchingKeyARN(selectedKey, aws.ToString(output.KeyId), region) {
			return nil, nil, invalid
		}
		codec, err := newSessionCipher(output.Plaintext)
		if err != nil {
			return nil, nil, invalid
		}
		return codec, bytes.Clone(output.CiphertextBlob), nil
	}
}
