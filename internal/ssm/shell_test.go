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

const safeShellDocument = `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":""}}`

func shellDocuments(name string) *documentAPI {
	return &documentAPI{response: &sdk.GetDocumentOutput{Name: aws.String(name), Content: aws.String(safeShellDocument), DocumentType: types.DocumentTypeSession, DocumentFormat: types.DocumentFormatJson, Status: types.DocumentStatusActive}}
}

func TestShellPreflightSelectionAndOwnedCapability(t *testing.T) {
	for _, name := range []string{"", "ReviewedShell", "arn:aws:ssm:ca-central-1:123456789012:document/ReviewedShell"} {
		t.Run(name, func(t *testing.T) {
			f, request := api(), input()
			expected := name
			if name == "" {
				expected = "SSM-SessionManagerRunShell"
			} else {
				request.DocumentName = aws.String(name)
			}
			d := shellDocuments(expected[strings.LastIndex(expected, "/")+1:])
			s, err := StartShell(context.Background(), f, d, request, "ca-central-1")
			if err != nil || s == nil || !s.HandshakeOptional() || f.starts != 1 {
				t.Fatalf("verified shell not authorized: %v", err)
			}
			if aws.ToString(d.input.Name) != expected || aws.ToString(d.input.DocumentVersion) != "$DEFAULT" || d.input.DocumentFormat != types.DocumentFormatJson || aws.ToString(request.DocumentName) != name || name == "" && request.DocumentName != nil {
				t.Fatal("preflight silently changed document selection")
			}
			if err := s.Terminate(context.Background()); err != nil || s.HandshakeOptional() {
				t.Fatal("terminated session still authorizes handshake-free shell")
			}
		})
	}
	plain, err := Start(context.Background(), api(), input(), "ca-central-1")
	if err != nil || plain.HandshakeOptional() || (&Session{}).HandshakeOptional() {
		t.Fatal("ordinary/unowned session authorizes handshake-free operation")
	}
}

type shellRead func(context.Context, *sdk.GetDocumentInput) (*sdk.GetDocumentOutput, error)

func (f shellRead) GetDocument(ctx context.Context, in *sdk.GetDocumentInput, _ ...func(*sdk.Options)) (*sdk.GetDocumentOutput, error) {
	return f(ctx, in)
}

func TestReadOnlyShellDocumentPreflightAndCancellation(t *testing.T) {
	doc := shellDocuments("SSM-SessionManagerRunShell")
	if err := ValidateShellDocument(context.Background(), doc, "", "ca-central-1"); err != nil || aws.ToString(doc.input.Name) != "SSM-SessionManagerRunShell" || aws.ToString(doc.input.DocumentVersion) != "$DEFAULT" {
		t.Fatal("read-only default preflight changed")
	}
	for _, during := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		reader := shellRead(func(context.Context, *sdk.GetDocumentInput) (*sdk.GetDocumentOutput, error) {
			calls++
			cancel()
			return doc.response, nil
		})
		if !during {
			cancel()
		}
		if err := ValidateShellDocument(ctx, reader, "", "ca-central-1"); !errors.Is(err, context.Canceled) || !during && calls != 0 {
			t.Fatal("canceled document was accepted or requested")
		}
	}
	if ValidateShellDocument(nil, doc, "", "ca-central-1") == nil || ValidateShellDocument(context.Background(), nil, "", "ca-central-1") == nil {
		t.Fatal("missing read-only dependencies accepted")
	}
}

func TestShellPreflightFailuresDoNotStart(t *testing.T) {
	for _, mutate := range []func(*documentAPI, *sdk.StartSessionInput){
		func(d *documentAPI, _ *sdk.StartSessionInput) { d.err = errors.New("synthetic-secret") },
		func(d *documentAPI, _ *sdk.StartSessionInput) { d.response = nil },
		func(d *documentAPI, _ *sdk.StartSessionInput) { d.response.Name = aws.String("OtherDocument") },
		func(d *documentAPI, _ *sdk.StartSessionInput) { d.response.Status = types.DocumentStatusUpdating },
		func(d *documentAPI, _ *sdk.StartSessionInput) { d.response.DocumentType = types.DocumentTypeCommand },
		func(d *documentAPI, _ *sdk.StartSessionInput) { d.response.DocumentFormat = types.DocumentFormatYaml },
		func(d *documentAPI, _ *sdk.StartSessionInput) {
			d.response.Content = aws.String(strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":"synthetic-secret"`, 1))
		},
		func(_ *documentAPI, r *sdk.StartSessionInput) { r.DocumentName = aws.String("bad/name") },
		func(_ *documentAPI, r *sdk.StartSessionInput) {
			r.Parameters = map[string][]string{"kmsKeyId": {"synthetic-secret"}}
		},
		func(_ *documentAPI, r *sdk.StartSessionInput) { r.Target = aws.String("invalid-target") },
	} {
		f, request, d := api(), input(), shellDocuments("SSM-SessionManagerRunShell")
		mutate(d, request)
		s, err := StartShell(context.Background(), f, d, request, "ca-central-1")
		if err == nil || s != nil || f.starts != 0 || f.terminates != 0 || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("unsafe preflight crossed ownership boundary: %v", err)
		}
		if (request.Parameters != nil || aws.ToString(request.Target) == "invalid-target" || aws.ToString(request.DocumentName) == "bad/name") && d.input != nil {
			t.Fatal("invalid shell setup reached AWS")
		}
	}
	f := api()
	f.startErr = errors.New("synthetic-secret")
	if s, err := StartShell(context.Background(), f, shellDocuments("SSM-SessionManagerRunShell"), input(), "ca-central-1"); s != nil || err == nil || f.terminates != 0 {
		t.Fatal("failed start manufactured ownership")
	}
	f = api()
	f.output.StreamUrl = aws.String("wss://attacker.invalid/")
	if s, err := StartShell(context.Background(), f, shellDocuments("SSM-SessionManagerRunShell"), input(), "ca-central-1"); s != nil || err == nil || f.terminates != 1 {
		t.Fatal("malformed owned response was not cleaned up")
	}
}

func TestShellDocumentEncryptionAndAmbiguityFailClosed(t *testing.T) {
	for _, content := range []string{
		"", "null", "[]", "{", safeShellDocument + `{}`, strings.Repeat("x", 65537),
		strings.Replace(safeShellDocument, `"1.0"`, `"2.0"`, 1),
		strings.Replace(safeShellDocument, `"Standard_Stream"`, `"NonInteractiveCommands"`, 1),
		strings.Replace(safeShellDocument, `"inputs"`, `"Inputs"`, 1),
		strings.Replace(safeShellDocument, `"inputs":{"kmsKeyId":""}`, `"inputs":null`, 1),
		strings.Replace(safeShellDocument, `"inputs":{"kmsKeyId":""}`, `"inputs":[]`, 1),
		strings.Replace(safeShellDocument, `"inputs":{"kmsKeyId":""}`, `"properties":{}`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":"synthetic-kms-key"`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":"{{ kms }}"`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":"{{ssm:key}}"`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"KmsKeyId":""`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":null`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":false`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":[]`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":"key","kmsKeyId":""`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":"key","KmsKeyId":""`, 1),
		strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"unknownEncryption":"key"`, 1),
		strings.Replace(safeShellDocument, `"inputs":`, `"unknown":0,"inputs":`, 1),
		strings.Replace(safeShellDocument, `"inputs":`, `"parameters":`+strings.Repeat("[", 18)+`0`+strings.Repeat("]", 18)+`,"inputs":`, 1),
	} {
		if err := validateShellContent(content); err == nil || strings.Contains(err.Error(), "synthetic-kms-key") {
			t.Fatal("ambiguous/encrypted document accepted or exposed")
		}
	}
	for _, content := range []string{safeShellDocument, `{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{}}`, `{"schemaVersion":"1.0","sessionType":"Standard_Stream","description":"regional preferences","parameters":{"bucket":{"type":"String","default":"logs"}},"inputs":{"kmsKeyId":"","s3BucketName":"{{bucket}}","s3KeyPrefix":"prefix","s3EncryptionEnabled":true,"cloudWatchLogGroupName":"group","cloudWatchEncryptionEnabled":true,"cloudWatchStreamingEnabled":true,"runAsEnabled":true,"runAsDefaultUser":"operator","idleSessionTimeout":"20","maxSessionDuration":"60","shellProfile":{"linux":"pwd; ls","windows":"date"}}}`} {
		if err := validateShellContent(content); err != nil {
			t.Fatal("non-KMS preferences should remain AWS/agent-enforced")
		}
	}
}

func FuzzShellDocument(f *testing.F) {
	f.Add(safeShellDocument)
	f.Add(`{"schemaVersion":"1.0","sessionType":"Standard_Stream","inputs":{"kmsKeyId":"alias/Reviewed"}}`)
	f.Add("null")
	f.Add("{")
	f.Fuzz(func(t *testing.T, content string) { _ = validateShellContent(content) })
}

func TestShellKMSDocumentOwnershipAndRegion(t *testing.T) {
	key := "arn:aws:kms:ca-central-1:123456789012:key/12345678-1234-1234-1234-123456789abc"
	for _, name := range []string{"", "ReviewedShell"} {
		request := input()
		if name != "" {
			request.DocumentName = aws.String(name)
		}
		expected := name
		if expected == "" {
			expected = "SSM-SessionManagerRunShell"
		}
		d := shellDocuments(expected)
		d.response.Content = aws.String(strings.Replace(safeShellDocument, `"kmsKeyId":""`, `"kmsKeyId":"`+key+`"`, 1))
		if err := ValidateShellDocument(context.Background(), d, name, "ca-central-1"); err != nil {
			t.Fatal("read-only KMS preflight failed")
		}
		f := api()
		s, err := StartShell(context.Background(), f, d, request, "ca-central-1")
		if err != nil || s == nil || s.HandshakeOptional() || s.ShellKMSKey() != key || aws.ToString(request.DocumentName) != name {
			t.Fatal("KMS ownership lost or handshake-free capability granted")
		}
		if err := s.Terminate(context.Background()); err != nil || s.ShellKMSKey() != "" {
			t.Fatal("terminated session retained KMS capability")
		}
		d.response.Content = aws.String(strings.Replace(aws.ToString(d.response.Content), "ca-central-1", "us-east-1", 1))
		f = api()
		if s, err := StartShell(context.Background(), f, d, request, "ca-central-1"); err == nil || s != nil || f.starts != 0 {
			t.Fatal("cross-region key reached StartSession")
		}
		if ValidateShellDocument(context.Background(), d, name, "ca-central-1") == nil {
			t.Fatal("read-only check ignored key region")
		}
	}
	plain, err := Start(context.Background(), api(), input(), "ca-central-1")
	if err != nil || plain.ShellKMSKey() != "" || (&Session{}).ShellKMSKey() != "" || (*Session)(nil).ShellKMSKey() != "" {
		t.Fatal("unverified session manufactured KMS capability")
	}
}
