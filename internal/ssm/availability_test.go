package ssm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func TestOnlineRejectsIncompleteOrAmbiguousResponses(t *testing.T) {
	valid := instanceInformation(1)
	id := aws.ToString(valid.InstanceId)
	for _, mode := range []string{"nil", "missing", "oversized", "unexpected", "duplicate", "later-duplicate", "later-error", "later-nil", "cycle-after-match", "large-token-after-match", "page-limit", "resource", "platform", "ping", "agent", "offline"} {
		t.Run(mode, func(t *testing.T) {
			api := &statusAPI{read: func(_ context.Context, _ *sdk.DescribeInstanceInformationInput, call int) (*sdk.DescribeInstanceInformationOutput, error) {
				info := valid
				switch mode {
				case "nil":
					return nil, nil
				case "missing":
					return &sdk.DescribeInstanceInformationOutput{}, nil
				case "oversized":
					return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: make([]types.InstanceInformation, 51)}, nil
				case "unexpected":
					info = instanceInformation(2)
				case "duplicate":
					return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{info, info}}, nil
				case "later-duplicate", "later-error", "later-nil", "cycle-after-match", "large-token-after-match", "page-limit":
					if call == 1 {
						return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{info}, NextToken: aws.String("synthetic-secret-token")}, nil
					}
					if mode == "later-error" {
						return nil, errors.New("synthetic-secret-error")
					}
					if mode == "later-nil" {
						return nil, nil
					}
					if mode == "cycle-after-match" {
						return &sdk.DescribeInstanceInformationOutput{NextToken: aws.String("synthetic-secret-token")}, nil
					}
					if mode == "large-token-after-match" {
						return &sdk.DescribeInstanceInformationOutput{NextToken: aws.String(strings.Repeat("x", 8193))}, nil
					}
					if mode == "page-limit" {
						return &sdk.DescribeInstanceInformationOutput{NextToken: aws.String(strconv.Itoa(call))}, nil
					}
				case "resource":
					info.ResourceType = types.ResourceTypeManagedInstance
				case "platform":
					info.PlatformType = "synthetic-secret-platform"
				case "ping":
					info.PingStatus = "synthetic-secret-ping"
				case "agent":
					info.AgentVersion = aws.String("synthetic-secret-version")
				case "offline":
					info.PingStatus = types.PingStatusConnectionLost
				}
				return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{info}}, nil
			}}
			info, err := Online(context.Background(), api, id)
			if err == nil || !reflect.DeepEqual(info, types.InstanceInformation{}) || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("availability accepted malformed/ambiguous/partial metadata or leaked it")
			}
			if mode == "page-limit" && api.calls != 1000 {
				t.Fatal("availability page bound changed")
			}
		})
	}
}

func TestOnlineContextAndAllowlistedResult(t *testing.T) {
	valid := instanceInformation(1)
	id := aws.ToString(valid.InstanceId)
	ctx, cancel := context.WithCancel(context.Background())
	api := &statusAPI{read: func(_ context.Context, in *sdk.DescribeInstanceInformationInput, call int) (*sdk.DescribeInstanceInformationOutput, error) {
		if aws.ToInt32(in.MaxResults) != 50 || len(in.Filters) != 1 || aws.ToString(in.Filters[0].Key) != "InstanceIds" || !reflect.DeepEqual(in.Filters[0].Values, []string{id}) {
			t.Fatal("availability broadened its target query")
		}
		if call == 1 {
			return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{valid}, NextToken: aws.String("page-two")}, nil
		}
		if call != 2 || aws.ToString(in.NextToken) != "page-two" {
			t.Fatal("availability failed complete pagination")
		}
		return &sdk.DescribeInstanceInformationOutput{}, nil
	}}
	valid.Name, valid.IPAddress, valid.ComputerName = aws.String("synthetic-secret-name"), aws.String("synthetic-secret-address"), aws.String("synthetic-secret-hostname")
	info, err := Online(ctx, api, id)
	if err != nil || info.Name != nil || info.IPAddress != nil || info.ComputerName != nil || aws.ToString(info.InstanceId) != id || aws.ToString(info.AgentVersion) != "3.3.1234.0" {
		t.Fatal("availability failed or returned arbitrary SDK fields")
	}
	cancel()
	if _, err := Online(ctx, api, id); !errors.Is(err, context.Canceled) || api.calls != 2 {
		t.Fatal("canceled check contacted AWS")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	api.read = func(context.Context, *sdk.DescribeInstanceInformationInput, int) (*sdk.DescribeInstanceInformationOutput, error) {
		cancel()
		return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{valid}}, nil
	}
	if info, err := Online(ctx, api, id); !errors.Is(err, context.Canceled) || info.InstanceId != nil {
		t.Fatal("AWS response bypassed concurrent cancellation")
	}
	if _, err := Online(context.Background(), nil, id); err == nil {
		t.Fatal("nil read-only client accepted")
	}
	if _, err := Online(context.Background(), api, "bad-id"); err == nil || api.calls != 3 {
		t.Fatal("invalid target contacted AWS")
	}
}

func TestOnlineActualSDKSerializationAndMetadata(t *testing.T) {
	const id = "i-0123456789abcdef0"
	client := sdk.NewFromConfig(aws.Config{Region: "ca-central-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", ""), HTTPClient: inventoryHTTP(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "ssm.ca-central-1.amazonaws.com" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatal("SDK availability request lost authenticated regional endpoint")
		}
		var query struct {
			MaxResults int
			Filters    []struct {
				Key    string
				Values []string
			}
		}
		if json.NewDecoder(r.Body).Decode(&query) != nil || query.MaxResults != 50 || len(query.Filters) != 1 || query.Filters[0].Key != "InstanceIds" || !reflect.DeepEqual(query.Filters[0].Values, []string{id}) {
			t.Fatal("SDK availability target query changed")
		}
		body := `{"InstanceInformationList":[{"InstanceId":"i-0123456789abcdef0","ResourceType":"EC2Instance","PingStatus":"Online","PlatformType":"Linux","AgentVersion":"3.3.1234.0","ComputerName":"synthetic-secret-hostname"}]}`
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})})
	info, err := Online(context.Background(), client, id)
	if err != nil || info.ComputerName != nil || info.PlatformType != types.PlatformTypeLinux {
		t.Fatal("actual SDK availability decoding failed or leaked arbitrary metadata")
	}
}
