package ssm

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/config"
	"ssmh/internal/logging"
)

// StartShell reads the selected shell document before starting an owned session.
// Only verified non-KMS Standard_Stream sessions may start without an application
// handshake, as the official agent does. This never alters account preferences.
// Document administrators remain trusted: StartSession cannot pin a version.
func StartShell(ctx context.Context, client API, documents DocumentAPI, input *sdk.StartSessionInput, region string) (*Session, error) {
	if input == nil || client == nil || documents == nil || len(input.Parameters) != 0 || !config.InstanceID(aws.ToString(input.Target)) {
		return nil, errors.New("invalid shell session setup")
	}
	if err := config.Region(region); err != nil {
		return nil, err
	}
	var selectedKey string
	if err := inspectShellDocument(ctx, documents, aws.ToString(input.DocumentName), func(content string) error {
		var err error
		selectedKey, err = shellContentKey(content)
		if err == nil && selectedKey != "" && !config.KMSKeyReference(selectedKey, region) {
			return errors.New("shell document KMS key does not match the selected region or partition")
		}
		return err
	}); err != nil {
		return nil, err
	}
	session, err := Start(ctx, client, input, region)
	if err != nil {
		return nil, err
	}
	session.handshakeOptional = selectedKey == ""
	if selectedKey != "" {
		session.kmsKey, session.kmsType = selectedKey, "Standard_Stream"
	}
	return session, nil
}

// ValidateShellDocument checks the selected default-version shell document
// through a read-only API. Empty name selects SSM-SessionManagerRunShell. It
// never starts a session, modifies preferences, or proves StartSession access.
// A later authorized document change cannot be ruled out by this preflight.
func ValidateShellDocument(ctx context.Context, documents DocumentAPI, name, region string) error {
	if err := config.Region(region); err != nil {
		return err
	}
	return inspectShellDocument(ctx, documents, name, func(content string) error {
		key, err := shellContentKey(content)
		if err == nil && key != "" && !config.KMSKeyReference(key, region) {
			return errors.New("shell document KMS key does not match the selected region or partition")
		}
		return err
	})
}

func inspectShellDocument(ctx context.Context, documents DocumentAPI, name string, inspect func(string) error) error {
	if ctx == nil || documents == nil {
		return errors.New("shell document context or client is unavailable")
	}
	if name == "" {
		name = "SSM-SessionManagerRunShell"
	}
	if !regexp.MustCompile(`^(?:[A-Za-z0-9_.-]{3,128}|arn:aws(?:-[a-z0-9-]+)?:ssm:[a-z0-9-]+:[0-9]{12}:document/[A-Za-z0-9_.-]{3,128})$`).MatchString(name) {
		return errors.New("invalid shell document name")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	response, err := documents.GetDocument(ctx, &sdk.GetDocumentInput{Name: aws.String(name), DocumentVersion: aws.String("$DEFAULT"), DocumentFormat: types.DocumentFormatJson})
	if err != nil {
		return errors.Join(ctx.Err(), logging.Failure("read SSM shell document (ssm:GetDocument is required)", err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	expectedName := name[strings.LastIndex(name, "/")+1:]
	if response == nil || response.DocumentType != types.DocumentTypeSession || response.DocumentFormat != types.DocumentFormatJson || response.Status != types.DocumentStatusActive || aws.ToString(response.Name) != expectedName {
		return errors.New("SSM returned an invalid or inactive shell document")
	}
	return inspect(aws.ToString(response.Content))
}

func validateShellContent(content string) error {
	_, err := shellContentKey(content)
	return err
}

func shellContentKey(content string) (selectedKey string, err error) {
	invalid := errors.New("shell document must be schema 1.0 Standard_Stream with known inputs and a literal supported KMS key or no key")
	// No partial key/capability can escape any parser failure.
	defer func() {
		if err != nil {
			selectedKey = ""
		}
	}()
	if len(content) == 0 || len(content) > 65536 || !utf8.ValidString(content) || !uniqueJSON([]byte(content)) {
		return "", invalid
	}
	// Exact keys avoid Go's case-insensitive struct decoding disagreeing with AWS.
	var document map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &document) != nil || document == nil {
		return "", invalid
	}
	for key := range document {
		switch key {
		case "schemaVersion", "description", "sessionType", "parameters", "inputs":
		default:
			return "", invalid
		}
	}
	var schema, sessionType string
	if json.Unmarshal(document["schemaVersion"], &schema) != nil || schema != "1.0" || json.Unmarshal(document["sessionType"], &sessionType) != nil || sessionType != "Standard_Stream" {
		return "", invalid
	}
	return sessionInputKey(document["inputs"])
}

// sessionInputKey preserves known server-owned preferences and grants only a
// literal key selection. It is shared by shell and command document preflight.
func sessionInputKey(raw json.RawMessage) (selectedKey string, err error) {
	invalid := errors.New("session document requires known inputs and a literal supported KMS key or no key")
	var inputs map[string]json.RawMessage
	if json.Unmarshal(raw, &inputs) != nil || inputs == nil {
		return "", invalid
	}
	for key, value := range inputs {
		switch key {
		case "kmsKeyId":
			// Missing/empty selects no KMS. A nonempty key must be literal;
			// parameter expressions, null and all other types fail closed.
			var kms *string
			if json.Unmarshal(value, &kms) != nil || kms == nil || *kms != "" && !config.KMSKeyReference(*kms, "") {
				return "", invalid
			}
			selectedKey = *kms
		case "s3BucketName", "s3KeyPrefix", "s3EncryptionEnabled", "cloudWatchLogGroupName", "cloudWatchEncryptionEnabled", "cloudWatchStreamingEnabled", "runAsEnabled", "runAsDefaultUser", "idleSessionTimeout", "maxSessionDuration", "shellProfile":
			// AWS/agent enforce these preferences. Do not rewrite logging, run-as,
			// profile commands or timeouts to accommodate the local client.
		default:
			return "", invalid
		}
	}
	return selectedKey, nil
}
