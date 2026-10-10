package ssm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/config"
	"ssmh/internal/logging"
)

// DocumentAPI is the authenticated read-only session-document boundary.
type DocumentAPI interface {
	GetDocument(context.Context, *sdk.GetDocumentInput, ...func(*sdk.Options)) (*sdk.GetDocumentOutput, error)
}

// ValidateCommandDocument reads the selected default document before execution.
// It never changes documents or privileges. Document administrators remain
// trusted: StartSession cannot pin a version, so a concurrent default-version
// change cannot be ruled out by this preflight check.
func ValidateCommandDocument(ctx context.Context, client DocumentAPI, name string) error {
	_, err := inspectCommandDocument(ctx, client, name, "")
	return err
}

// StartCommand verifies a non-elevated separate-output document and retains its
// literal KMS selection only on the resulting owned command session. It never
// executes a local command or changes document/preferences/permissions.
func StartCommand(ctx context.Context, client API, documents DocumentAPI, input *sdk.StartSessionInput, region string) (*Session, error) {
	if input == nil || client == nil || documents == nil || !config.InstanceID(aws.ToString(input.Target)) || len(input.Parameters) != 1 || len(input.Parameters["command"]) != 1 {
		return nil, errors.New("invalid command session setup")
	}
	command := input.Parameters["command"][0]
	if command == "" || len(command) > 32768 || !utf8.ValidString(command) || strings.ContainsRune(command, 0) {
		return nil, errors.New("invalid command session parameter")
	}
	if err := config.Region(region); err != nil {
		return nil, err
	}
	key, err := inspectCommandDocument(ctx, documents, aws.ToString(input.DocumentName), region)
	if err != nil {
		return nil, err
	}
	session, err := Start(ctx, client, input, region)
	if err != nil {
		return nil, err
	}
	if key != "" {
		session.kmsKey, session.kmsType = key, "NonInteractiveCommands"
	}
	return session, nil
}

func inspectCommandDocument(ctx context.Context, client DocumentAPI, name, region string) (string, error) {
	if ctx == nil || client == nil {
		return "", errors.New("command document context or client is unavailable")
	}
	if !regexp.MustCompile(`^(?:[A-Za-z0-9_.-]{3,128}|arn:aws(?:-[a-z0-9-]+)?:ssm:[a-z0-9-]+:[0-9]{12}:document/[A-Za-z0-9_.-]{3,128})$`).MatchString(name) {
		return "", errors.New("invalid command document name")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	response, err := client.GetDocument(ctx, &sdk.GetDocumentInput{Name: aws.String(name), DocumentVersion: aws.String("$DEFAULT"), DocumentFormat: types.DocumentFormatJson})
	if err != nil {
		return "", errors.Join(ctx.Err(), logging.Failure("read SSM command document", err))
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	expectedName := name[strings.LastIndex(name, "/")+1:]
	if response == nil || response.DocumentType != types.DocumentTypeSession || response.DocumentFormat != types.DocumentFormatJson || response.Status != types.DocumentStatusActive || aws.ToString(response.Name) != expectedName {
		return "", errors.New("SSM returned an invalid or inactive command document")
	}
	content := aws.ToString(response.Content)
	if err := validateCommandContent(content); err != nil {
		return "", err
	}
	var document map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &document) != nil {
		return "", errors.New("invalid command document")
	}
	if raw, present := document["inputs"]; present {
		key, err := sessionInputKey(raw)
		if err != nil {
			return "", err
		}
		if key != "" && !config.KMSKeyReference(key, region) {
			return "", errors.New("command document KMS key does not match the selected region or partition")
		}
		return key, nil
	}
	return "", nil
}

func validateCommandContent(content string) error {
	invalid := errors.New("command document must be NonInteractiveCommands with unchanged command parameter, no elevation, separate output and empty prefixes; see docs/remote-commands.md")
	if len(content) == 0 || len(content) > 65536 || !utf8.ValidString(content) || !uniqueJSON([]byte(content)) || !exactCommandFields([]byte(content)) {
		return invalid
	}
	type properties struct {
		Commands     string `json:"commands"`
		Elevated     *bool  `json:"runAsElevated"`
		Separate     *bool  `json:"separateOutputStream"`
		StdoutPrefix string `json:"stdOutSeparatorPrefix"`
		StderrPrefix string `json:"stdErrSeparatorPrefix"`
	}
	var document struct {
		Schema      string          `json:"schemaVersion"`
		Description string          `json:"description"`
		SessionType string          `json:"sessionType"`
		Inputs      json.RawMessage `json:"inputs"`
		Parameters  map[string]struct {
			Type           string          `json:"type"`
			Description    string          `json:"description"`
			Default        json.RawMessage `json:"default"`
			AllowedPattern string          `json:"allowedPattern"`
			AllowedValues  []string        `json:"allowedValues"`
			MinChars       int             `json:"minChars"`
			MaxChars       int             `json:"maxChars"`
		} `json:"parameters"`
		Properties struct {
			Linux   properties      `json:"linux"`
			Windows json.RawMessage `json:"windows"`
			MacOS   json.RawMessage `json:"macos"`
		} `json:"properties"`
	}
	decoder := json.NewDecoder(bytes.NewBufferString(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || document.Schema != "1.0" || document.SessionType != "NonInteractiveCommands" || document.Parameters["command"].Type != "String" {
		return invalid
	}
	linux := document.Properties.Linux
	if linux.Commands != "{{ command }}" || linux.Elevated == nil || *linux.Elevated || linux.Separate == nil || !*linux.Separate || linux.StdoutPrefix != "" || linux.StderrPrefix != "" {
		return invalid
	}
	if len(document.Inputs) != 0 {
		if _, err := sessionInputKey(document.Inputs); err != nil {
			return invalid
		}
	}
	return nil
}

// exactCommandFields avoids encoding/json's case-insensitive struct matching
// at every Linux command-policy boundary. Other-platform content and inputs
// remain server-owned; they cannot authorize a Linux command property here.
func exactCommandFields(content []byte) bool {
	object := func(raw []byte, allowed ...string) (map[string]json.RawMessage, bool) {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return nil, false
		}
		for key := range fields {
			found := false
			for _, name := range allowed {
				if key == name {
					found = true
					break
				}
			}
			if !found {
				return nil, false
			}
		}
		return fields, true
	}
	document, ok := object(content, "schemaVersion", "description", "sessionType", "inputs", "parameters", "properties")
	if !ok {
		return false
	}
	var parameters map[string]json.RawMessage
	if json.Unmarshal(document["parameters"], &parameters) != nil || parameters == nil {
		return false
	}
	for _, parameter := range parameters {
		if _, ok := object(parameter, "type", "description", "default", "allowedPattern", "allowedValues", "minChars", "maxChars"); !ok {
			return false
		}
	}
	properties, ok := object(document["properties"], "linux", "windows", "macos")
	if !ok {
		return false
	}
	linux, ok := object(properties["linux"], "commands", "runAsElevated", "separateOutputStream", "stdOutSeparatorPrefix", "stdErrSeparatorPrefix")
	if !ok {
		return false
	}
	for _, key := range []string{"stdOutSeparatorPrefix", "stdErrSeparatorPrefix"} {
		if raw, present := linux[key]; present {
			var value *string
			if json.Unmarshal(raw, &value) != nil || value == nil {
				return false
			}
		}
	}
	return true
}

// uniqueJSON rejects duplicate keys and excessive nesting rather than relying
// on potentially different duplicate-field interpretation across AWS/agent.
func uniqueJSON(content []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(content))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delimiter, nested := token.(json.Delim)
		if !nested {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				token, err := decoder.Token()
				key, ok := token.(string)
				key = strings.ToLower(key)
				if err != nil || !ok || seen[key] {
					return false
				}
				seen[key] = true
				if !value(depth + 1) {
					return false
				}
			}
		case '[':
			for decoder.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		end, err := decoder.Token()
		return err == nil && (delimiter == '{' && end == json.Delim('}') || delimiter == '[' && end == json.Delim(']'))
	}
	if !value(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}
