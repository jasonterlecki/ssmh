package ssm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const safeCommandDocument = `{"schemaVersion":"1.0","sessionType":"NonInteractiveCommands","parameters":{"command":{"type":"String"}},"properties":{"linux":{"commands":"{{ command }}","runAsElevated":false,"separateOutputStream":true}}}`

type documentAPI struct {
	response *sdk.GetDocumentOutput
	err      error
	input    *sdk.GetDocumentInput
}

func (d *documentAPI) GetDocument(_ context.Context, in *sdk.GetDocumentInput, _ ...func(*sdk.Options)) (*sdk.GetDocumentOutput, error) {
	d.input = in
	return d.response, d.err
}

func TestCommandDocumentReadAndValidation(t *testing.T) {
	for _, name := range []string{"SafeCommand", "arn:aws:ssm:ca-central-1:123456789012:document/SafeCommand"} {
		api := &documentAPI{response: &sdk.GetDocumentOutput{Name: aws.String("SafeCommand"), Content: aws.String(safeCommandDocument), DocumentType: types.DocumentTypeSession, DocumentFormat: types.DocumentFormatJson, Status: types.DocumentStatusActive}}
		if err := ValidateCommandDocument(context.Background(), api, name); err != nil {
			t.Fatal(err)
		}
		if aws.ToString(api.input.Name) != name || aws.ToString(api.input.DocumentVersion) != "$DEFAULT" || api.input.DocumentFormat != types.DocumentFormatJson {
			t.Fatal("document selection changed")
		}
		api.response.Status = types.DocumentStatusUpdating
		if err := ValidateCommandDocument(context.Background(), api, name); err == nil {
			t.Fatal("inactive document accepted")
		}
		api.response = nil
		if err := ValidateCommandDocument(context.Background(), api, name); err == nil {
			t.Fatal("missing document accepted")
		}
	}
	api := &documentAPI{err: errors.New("synthetic-secret")}
	if err := ValidateCommandDocument(context.Background(), api, "SafeCommand"); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("API error exposed")
	}
	api.input = nil
	if err := ValidateCommandDocument(context.Background(), api, "bad/document"); err == nil || api.input != nil {
		t.Fatal("invalid document reached AWS")
	}
}

func TestUnsafeCommandDocumentsFailClosed(t *testing.T) {
	for _, content := range []string{
		"", "{", "null", safeCommandDocument + `{}`, strings.Repeat("x", 65537),
		strings.Replace(safeCommandDocument, `"1.0"`, `"2.0"`, 1),
		strings.Replace(safeCommandDocument, `"NonInteractiveCommands"`, `"InteractiveCommands"`, 1),
		strings.Replace(safeCommandDocument, `"String"`, `"StringList"`, 1),
		strings.Replace(safeCommandDocument, `{{ command }}`, `sudo {{ command }}`, 1),
		strings.Replace(safeCommandDocument, `false`, `true`, 1),
		strings.Replace(safeCommandDocument, `"runAsElevated":false,`, ``, 1),
		strings.Replace(safeCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":false`, 1),
		strings.Replace(safeCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":"true"`, 1),
		strings.Replace(safeCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":true,"stdErrSeparatorPrefix":"prefix"`, 1),
		strings.Replace(safeCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":true,"unknown":true`, 1),
		strings.Replace(safeCommandDocument, `"runAsElevated":false`, `"runAsElevated":true,"runAsElevated":false`, 1),
		strings.Replace(safeCommandDocument, `"runAsElevated":false`, `"RunAsElevated":true,"runAsElevated":false`, 1),
		strings.Replace(safeCommandDocument, `"parameters":`, `"inputs":`+strings.Repeat("[", 18)+`0`+strings.Repeat("]", 18)+`,"parameters":`, 1),
	} {
		if err := validateCommandContent(content); err == nil || strings.Contains(err.Error(), content) && len(content) > 250 {
			t.Fatal("unsafe document accepted or exposed")
		}
	}
}

func FuzzCommandDocument(f *testing.F) {
	f.Add(safeCommandDocument)
	f.Add(strings.Replace(safeCommandDocument, `"runAsElevated"`, `"RunAsElevated"`, 1))
	f.Add(strings.Replace(safeCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":true,"stdErrSeparatorPrefix":null`, 1))
	f.Add("{")
	f.Add("null")
	f.Fuzz(func(t *testing.T, content string) { _ = validateCommandContent(content) })
}

func TestCommandDocumentExactPolicyFields(t *testing.T) {
	if err := validateCommandContent(strings.Replace(safeCommandDocument, `"commands"`, `"\u0063ommands"`, 1)); err != nil {
		t.Fatal("escaped exact policy field rejected")
	}
	for _, key := range []string{"schemaVersion", "sessionType", "parameters", "properties", "command", "type", "linux", "commands", "runAsElevated", "separateOutputStream"} {
		t.Run(key, func(t *testing.T) {
			content := strings.Replace(safeCommandDocument, `"`+key+`"`, `"`+strings.ToUpper(key[:1])+key[1:]+`"`, 1)
			if validateCommandContent(content) == nil {
				t.Fatal("case-variant policy field accepted")
			}
		})
	}
	for _, key := range []string{"stdOutSeparatorPrefix", "stdErrSeparatorPrefix"} {
		for _, value := range []string{`null`, `false`, `[]`, `{}`, `"prefix"`} {
			content := strings.Replace(safeCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":true,"`+key+`":`+value, 1)
			if validateCommandContent(content) == nil {
				t.Fatal("invalid separator accepted")
			}
		}
		content := strings.Replace(safeCommandDocument, `"separateOutputStream":true`, `"separateOutputStream":true,"`+key+`":""`, 1)
		if err := validateCommandContent(content); err != nil {
			t.Fatal("explicit empty separator rejected")
		}
		content = strings.Replace(content, `"`+key+`"`, `"`+strings.ToUpper(key)+`"`, 1)
		if validateCommandContent(content) == nil {
			t.Fatal("case-variant separator accepted")
		}
	}
}

type cancelCommandDocument struct {
	documentAPI
	cancel context.CancelFunc
}

func (d *cancelCommandDocument) GetDocument(ctx context.Context, input *sdk.GetDocumentInput, opts ...func(*sdk.Options)) (*sdk.GetDocumentOutput, error) {
	d.cancel()
	return d.documentAPI.GetDocument(ctx, input, opts...)
}

func TestCommandDocumentCancellationBoundary(t *testing.T) {
	api := &documentAPI{response: &sdk.GetDocumentOutput{Name: aws.String("SafeCommand"), Content: aws.String(safeCommandDocument), DocumentType: types.DocumentTypeSession, DocumentFormat: types.DocumentFormatJson, Status: types.DocumentStatusActive}}
	if ValidateCommandDocument(nil, api, "SafeCommand") == nil || ValidateCommandDocument(context.Background(), nil, "SafeCommand") == nil {
		t.Fatal("missing context/client accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(ValidateCommandDocument(ctx, api, "SafeCommand"), context.Canceled) || api.input != nil {
		t.Fatal("canceled preflight reached API")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	canceled := &cancelCommandDocument{documentAPI: *api, cancel: cancel}
	if !errors.Is(ValidateCommandDocument(ctx, canceled, "SafeCommand"), context.Canceled) || canceled.input == nil {
		t.Fatal("post-response cancellation accepted")
	}
}

func TestStartCommandDocumentKMSOwnership(t *testing.T) {
	key := "arn:aws:kms:ca-central-1:123456789012:key/12345678-1234-1234-1234-123456789abc"
	withInputs := func(inputs string) string {
		return strings.Replace(safeCommandDocument, `"parameters":`, `"inputs":`+inputs+`,"parameters":`, 1)
	}
	for _, selected := range []string{"", key, "alias/reviewed", "12345678-1234-1234-1234-123456789abc"} {
		d := shellDocuments("ReviewedCommand")
		d.response.Content = aws.String(withInputs(`{"kmsKeyId":"` + selected + `","runAsEnabled":true}`))
		f := api()
		request := &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0"), DocumentName: aws.String("ReviewedCommand"), Parameters: map[string][]string{"command": {"/bin/sh -c 'exit 37'"}}}
		s, err := StartCommand(context.Background(), f, d, request, "ca-central-1")
		if err != nil || s == nil || f.starts != 1 || s.HandshakeOptional() || s.ShellKMSKey() != "" {
			t.Fatal("command ownership/handshake boundary failed")
		}
		kind, actual := s.DocumentKMSContext()
		if actual != selected || selected != "" && kind != "NonInteractiveCommands" || selected == "" && kind != "" {
			t.Fatal("command KMS selection changed")
		}
		f.terminateErr = errors.New("synthetic cleanup failure")
		if s.Terminate(context.Background()) == nil {
			t.Fatal("cleanup unexpectedly passed")
		}
		if _, actual := s.DocumentKMSContext(); actual != selected {
			t.Fatal("failed cleanup dropped live capability")
		}
		f.terminateErr = nil
		if s.Terminate(context.Background()) != nil {
			t.Fatal("owned cleanup failed")
		}
		if kind, key := s.DocumentKMSContext(); kind != "" || key != "" {
			t.Fatal("terminated command retained capability")
		}
	}
	for _, raw := range []string{`null`, `[]`, `{"kmsKeyId":null}`, `{"kmsKeyId":"{{ key }}"}`, `{"KmsKeyId":"alias/key"}`, `{"kmsKeyId":"` + strings.Replace(key, "ca-central-1", "us-east-1", 1) + `"}`, `{"kmsKeyId":"alias/key","unknown":true}`} {
		d := shellDocuments("ReviewedCommand")
		d.response.Content = aws.String(withInputs(raw))
		f := api()
		request := &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0"), DocumentName: aws.String("ReviewedCommand"), Parameters: map[string][]string{"command": {"exit 37"}}}
		if s, err := StartCommand(context.Background(), f, d, request, "ca-central-1"); err == nil || s != nil || f.starts != 0 {
			t.Fatal("unverified key/inputs reached StartSession")
		}
	}
	for _, session := range []*Session{nil, {}} {
		if kind, key := session.DocumentKMSContext(); kind != "" || key != "" {
			t.Fatal("unowned session granted document capability")
		}
	}
	ordinary, err := Start(context.Background(), api(), &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0")}, "ca-central-1")
	if err != nil {
		t.Fatal("ordinary owned fixture failed")
	}
	if kind, key := ordinary.DocumentKMSContext(); kind != "" || key != "" {
		t.Fatal("ordinary Start granted document capability")
	}
}

func TestStartCommandInvalidInputBeforeDocumentRead(t *testing.T) {
	for _, change := range []func(*sdk.StartSessionInput){
		func(in *sdk.StartSessionInput) { in.Target = nil },
		func(in *sdk.StartSessionInput) { in.Parameters = nil },
		func(in *sdk.StartSessionInput) { in.Parameters["command"] = nil },
		func(in *sdk.StartSessionInput) { in.Parameters["command"] = []string{"one", "two"} },
		func(in *sdk.StartSessionInput) { in.Parameters["other"] = []string{"value"} },
		func(in *sdk.StartSessionInput) { in.Parameters["command"] = []string{""} },
		func(in *sdk.StartSessionInput) { in.Parameters["command"] = []string{"bad\x00command"} },
		func(in *sdk.StartSessionInput) { in.Parameters["command"] = []string{"\xff"} },
		func(in *sdk.StartSessionInput) { in.Parameters["command"] = []string{strings.Repeat("x", 32769)} },
	} {
		in := &sdk.StartSessionInput{Target: aws.String("i-0123456789abcdef0"), DocumentName: aws.String("ReviewedCommand"), Parameters: map[string][]string{"command": {"exit 37"}}}
		change(in)
		d := shellDocuments("ReviewedCommand")
		f := api()
		if s, err := StartCommand(context.Background(), f, d, in, "ca-central-1"); err == nil || s != nil || f.starts != 0 || d.input != nil {
			t.Fatal("invalid command input reached document/session API")
		}
	}
}
