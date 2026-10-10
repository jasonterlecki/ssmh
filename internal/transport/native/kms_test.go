package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go/logging"
	"ssmh/internal/ssm"
)

const dataKeyID = "12345678-1234-1234-1234-123456789abc"
const dataKeyARN = "arn:aws:kms:ca-central-1:123456789012:key/" + dataKeyID
const dataKeyTarget = "i-0123456789abcdef0"

func ownedKeySession(t *testing.T) *ssm.Session {
	t.Helper()
	s, err := ssm.Start(context.Background(), startAPI{}, &sdk.StartSessionInput{Target: aws.String(dataKeyTarget)}, "ca-central-1")
	if err != nil {
		t.Fatal("synthetic ownership creation failed")
	}
	t.Cleanup(func() {
		if err := s.Terminate(context.Background()); err != nil {
			t.Fatal("synthetic ownership cleanup failed")
		}
	})
	return s
}

type dataKeyFunc func(context.Context, *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)

func (f dataKeyFunc) GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	return f(ctx, in)
}

func validDataKeyOutput() *kms.GenerateDataKeyOutput {
	return &kms.GenerateDataKeyOutput{KeyId: aws.String(dataKeyARN), Plaintext: syntheticSessionMaterial(), CiphertextBlob: []byte("synthetic-kms-ciphertext")}
}

func TestOwnedKMSKeyPreparationContextAndClear(t *testing.T) {
	for _, challenge := range []string{"", testKMSChallenge} {
		s := ownedKeySession(t)
		output := validDataKeyOutput()
		calls := 0
		deadline := time.Now().Add(time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		prepare := ownedKeyPreparer(ctx, dataKeyFunc(func(callCtx context.Context, in *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
			calls++
			expected := map[string]string{"aws:ssm:SessionId": ownedID, "aws:ssm:TargetId": dataKeyTarget}
			if challenge != "" {
				expected["aws:ssm:RandomChallenge"] = challenge
			}
			actual, ok := callCtx.Deadline()
			if !ok || actual.After(deadline) || aws.ToString(in.KeyId) != dataKeyID || aws.ToInt32(in.NumberOfBytes) != 64 || in.KeySpec != "" || in.Recipient != nil || len(in.GrantTokens) != 0 || !reflect.DeepEqual(in.EncryptionContext, expected) {
				t.Fatal("key request changed selected key, bound context or deadline")
			}
			return output, nil
		}), s, dataKeyID, "ca-central-1")
		codec, blob, err := prepare(kmsParameters{dataKeyID, challenge})
		if err != nil || codec == nil || string(blob) != "synthetic-kms-ciphertext" || !bytes.Equal(output.Plaintext, make([]byte, 64)) {
			t.Fatal("key preparation failed or retained SDK plaintext")
		}
		defer codec.clear()
		clear(output.CiphertextBlob)
		if string(blob) != "synthetic-kms-ciphertext" {
			t.Fatal("returned ciphertext aliases SDK response")
		}
		if plain, err := codec.decrypt(referencePayload(t, syntheticSessionMaterial()[:32], []byte("data"))); err != nil || string(plain) != "data" {
			t.Fatal("clearing SDK plaintext corrupted cipher")
		}
		if next, data, err := prepare(kmsParameters{dataKeyID, challenge}); err == nil || next != nil || data != nil || calls != 1 {
			t.Fatal("key preparer reused")
		}
	}
}

func TestOwnedKMSKeyFailureClearAndRedaction(t *testing.T) {
	for _, mode := range []string{"error", "nil", "short", "long", "equal halves", "empty blob", "large blob", "recipient", "wrong key", "wrong region", "cancel after", "terminate after"} {
		t.Run(mode, func(t *testing.T) {
			s := ownedKeySession(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			output := validDataKeyOutput()
			prepare := ownedKeyPreparer(ctx, dataKeyFunc(func(context.Context, *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
				switch mode {
				case "error":
					return output, errors.New("SYNTHETIC-SECRET-SDK-ERROR")
				case "nil":
					return nil, nil
				case "short":
					output.Plaintext = make([]byte, 63)
				case "long":
					output.Plaintext = make([]byte, 65)
				case "equal halves":
					output.Plaintext = bytes.Repeat([]byte{9}, 64)
				case "empty blob":
					output.CiphertextBlob = nil
				case "large blob":
					output.CiphertextBlob = make([]byte, 6145)
				case "recipient":
					output.CiphertextForRecipient = []byte("unexpected")
				case "wrong key":
					output.KeyId = aws.String(strings.Replace(dataKeyARN, dataKeyID, "abcdefab-1234-1234-1234-123456789abc", 1))
				case "wrong region":
					output.KeyId = aws.String(strings.Replace(dataKeyARN, "ca-central-1", "us-east-1", 1))
				case "cancel after":
					cancel()
				case "terminate after":
					if err := s.Terminate(context.Background()); err != nil {
						t.Fatal("synthetic terminate failed")
					}
				}
				return output, nil
			}), s, dataKeyID, "ca-central-1")
			codec, blob, err := prepare(kmsParameters{dataKeyID, ""})
			if codec != nil || blob != nil || err == nil || err.Error() != "KMS session key preparation failed" {
				t.Fatal("invalid key response accepted/disclosed")
			}
			if mode != "nil" && !bytes.Equal(output.Plaintext, make([]byte, len(output.Plaintext))) {
				t.Fatal("failure retained partial SDK plaintext")
			}
		})
	}
}

func TestOwnedKMSValidationBeforeSideEffects(t *testing.T) {
	for _, mode := range []string{"cancel", "terminated", "wrong key", "bad challenge", "wrong region"} {
		t.Run(mode, func(t *testing.T) {
			s := ownedKeySession(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			parameters := kmsParameters{dataKeyID, ""}
			region := "ca-central-1"
			switch mode {
			case "cancel":
				cancel()
			case "terminated":
				if err := s.Terminate(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "wrong key":
				parameters.keyID = "other"
			case "bad challenge":
				parameters.challenge = "secret"
			case "wrong region":
				region = "us-east-1"
			}
			calls := 0
			prepare := ownedKeyPreparer(ctx, dataKeyFunc(func(context.Context, *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
				calls++
				return validDataKeyOutput(), nil
			}), s, dataKeyID, region)
			if codec, blob, err := prepare(parameters); err == nil || codec != nil || blob != nil || calls != 0 {
				t.Fatal("invalid preparation caused a key-generation side effect")
			}
		})
	}
}

type kmsHTTPFunc func(*http.Request) (*http.Response, error)

func (f kmsHTTPFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestKMSSelectedSDKSigningAndSerialization(t *testing.T) {
	s := ownedKeySession(t)
	calls := 0
	logs := 0
	provider := credentials.NewStaticCredentialsProvider("SYNTHETIC-SELECTED-KEY", "synthetic-secret", "synthetic-token")
	cfg := aws.Config{Region: "ca-central-1", Credentials: provider, RetryMaxAttempts: 1,
		ClientLogMode: aws.LogSigning | aws.LogRequestWithBody | aws.LogResponseWithBody,
		Logger:        logging.LoggerFunc(func(logging.Classification, string, ...interface{}) { logs++ }),
		HTTPClient: kmsHTTPFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Scheme != "https" || r.URL.Host != "kms.ca-central-1.amazonaws.com" || !strings.Contains(r.Header.Get("Authorization"), "Credential=SYNTHETIC-SELECTED-KEY/") || !strings.Contains(r.Header.Get("Authorization"), "/ca-central-1/kms/aws4_request") || r.Header.Get("X-Amz-Security-Token") != "synthetic-token" || r.Header.Get("X-Amz-Target") != "TrentService.GenerateDataKey" {
				t.Fatal("KMS client changed identity, endpoint, region or operation")
			}
			var input struct {
				KeyId             string
				NumberOfBytes     int
				EncryptionContext map[string]string
			}
			if json.NewDecoder(r.Body).Decode(&input) != nil || input.KeyId != dataKeyARN || input.NumberOfBytes != 64 || input.EncryptionContext["aws:ssm:RandomChallenge"] != testKMSChallenge || input.EncryptionContext["aws:ssm:SessionId"] != ownedID || input.EncryptionContext["aws:ssm:TargetId"] != dataKeyTarget {
				t.Fatal("SDK key request context/serialization changed")
			}
			body, _ := json.Marshal(map[string]any{"KeyId": dataKeyARN, "Plaintext": syntheticSessionMaterial(), "CiphertextBlob": []byte("synthetic-ciphertext")})
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
		})}
	prepare, err := newKMSPreparer(context.Background(), cfg, s, dataKeyARN)
	if err != nil {
		t.Fatal("selected SDK configuration refused")
	}
	codec, blob, err := prepare(kmsParameters{dataKeyARN, testKMSChallenge})
	if err != nil || codec == nil || string(blob) != "synthetic-ciphertext" || calls != 1 || logs != 0 {
		t.Fatal("selected SDK key generation failed")
	}
	codec.clear()
	for _, selected := range []string{dataKeyID, dataKeyARN, "alias/Selected", "arn:aws:kms:ca-central-1:123456789012:alias/Selected"} {
		if !keyReference(selected, cfg.Region) || !matchingKeyARN(selected, dataKeyARN, cfg.Region) {
			t.Fatal("documented KMS reference refused")
		}
	}
	for _, selected := range []string{"", "secret\nkey", strings.Repeat("a", 2049), "arn:aws:kms:us-east-1:123456789012:key/" + dataKeyID, "arn:aws-cn:kms:ca-central-1:123456789012:key/" + dataKeyID} {
		if next, err := newKMSPreparer(context.Background(), cfg, s, selected); err == nil || next != nil {
			t.Fatal("unsafe/mismatched key reference accepted")
		}
	}
	if err := s.Terminate(context.Background()); err != nil {
		t.Fatal("synthetic terminate failed")
	}
	if next, err := newKMSPreparer(context.Background(), cfg, s, dataKeyARN); err == nil || next != nil {
		t.Fatal("terminated ownership enabled KMS")
	}
}
