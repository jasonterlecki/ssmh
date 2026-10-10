package ssm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type inventoryHTTP func(*http.Request) (*http.Response, error)

func (f inventoryHTTP) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestInventoryThroughSDKRequestSerialization(t *testing.T) {
	calls := 0
	client := sdk.NewFromConfig(aws.Config{Region: "ca-central-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", ""), HTTPClient: inventoryHTTP(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != "POST" || request.URL.Scheme != "https" || request.URL.Host != "ssm.ca-central-1.amazonaws.com" || request.Header.Get("X-Amz-Target") != "AmazonSSM.DescribeInstanceInformation" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatal("SDK request did not use the authenticated regional SSM API")
		}
		var query struct {
			MaxResults int
			Filters    []struct {
				Key    string
				Values []string
			}
			NextToken string
		}
		if err := json.NewDecoder(request.Body).Decode(&query); err != nil {
			t.Fatal(err)
		}
		if query.MaxResults != 50 || len(query.Filters) != 1 || query.Filters[0].Key != "ResourceType" || len(query.Filters[0].Values) != 1 || query.Filters[0].Values[0] != "EC2Instance" || calls == 1 && query.NextToken != "" || calls == 2 && query.NextToken != "next-page" || calls > 2 {
			t.Fatal("SDK serialization changed inventory filters or pagination")
		}
		body := `{"InstanceInformationList":[],"NextToken":"next-page"}`
		if calls == 2 {
			body = `{"InstanceInformationList":[{"InstanceId":"i-0123456789abcdef0","ResourceType":"EC2Instance","PingStatus":"Online","PlatformType":"Linux","AgentVersion":"3.3.1234.0"}]}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})})
	rows, err := Inventory(context.Background(), client)
	if err != nil || calls != 2 || len(rows) != 1 || rows[0].InstanceID != "i-0123456789abcdef0" || rows[0].AgentVersion != "3.3.1234.0" {
		t.Fatalf("SDK inventory response not interpreted: %v", err)
	}
}

type statusAPI struct {
	calls int
	read  func(context.Context, *sdk.DescribeInstanceInformationInput, int) (*sdk.DescribeInstanceInformationOutput, error)
}

func (s *statusAPI) DescribeInstanceInformation(ctx context.Context, input *sdk.DescribeInstanceInformationInput, _ ...func(*sdk.Options)) (*sdk.DescribeInstanceInformationOutput, error) {
	s.calls++
	return s.read(ctx, input, s.calls)
}

func instanceInformation(number int) types.InstanceInformation {
	return types.InstanceInformation{InstanceId: aws.String(fmt.Sprintf("i-%017x", number)), ResourceType: types.ResourceTypeEc2Instance, PingStatus: types.PingStatusOnline, PlatformType: types.PlatformTypeLinux, AgentVersion: aws.String("3.3.1234.0")}
}

func TestInventoryPaginationReadOnlyAndSorted(t *testing.T) {
	api := &statusAPI{read: func(ctx context.Context, in *sdk.DescribeInstanceInformationInput, call int) (*sdk.DescribeInstanceInformationOutput, error) {
		if ctx.Err() != nil || aws.ToInt32(in.MaxResults) != 50 || len(in.Filters) != 1 || aws.ToString(in.Filters[0].Key) != "ResourceType" || len(in.Filters[0].Values) != 1 || in.Filters[0].Values[0] != "EC2Instance" || len(in.InstanceInformationFilterList) != 0 {
			t.Fatal("inventory changed its read-only query")
		}
		switch call {
		case 1:
			if in.NextToken != nil {
				t.Fatal("initial token supplied")
			}
			return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{instanceInformation(2)}, NextToken: aws.String("page-two")}, nil
		case 2:
			if aws.ToString(in.NextToken) != "page-two" {
				t.Fatal("token changed")
			}
			return &sdk.DescribeInstanceInformationOutput{NextToken: aws.String("page-three")}, nil
		case 3:
			if aws.ToString(in.NextToken) != "page-three" {
				t.Fatal("empty page stopped pagination")
			}
			info := instanceInformation(1)
			info.PlatformType, info.PingStatus = types.PlatformTypeWindows, types.PingStatusConnectionLost
			info.Name, info.IPAddress = aws.String("synthetic-secret"), aws.String("synthetic-secret")
			return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{info}}, nil
		default:
			t.Fatal("unexpected page")
			return nil, nil
		}
	}}
	rows, err := Inventory(context.Background(), api)
	if err != nil || len(rows) != 2 || api.calls != 3 || rows[0].InstanceID != "i-00000000000000001" || rows[0].PingStatus != types.PingStatusConnectionLost || rows[0].Platform != types.PlatformTypeWindows || rows[1].PingStatus != types.PingStatusOnline {
		t.Fatalf("inventory not preserved/sorted: %v", err)
	}
	if strings.Contains(fmt.Sprint(rows), "synthetic-secret") {
		t.Fatal("unused SDK metadata retained")
	}
	api.read = func(context.Context, *sdk.DescribeInstanceInformationInput, int) (*sdk.DescribeInstanceInformationOutput, error) {
		return &sdk.DescribeInstanceInformationOutput{}, nil
	}
	rows, err = Inventory(context.Background(), api)
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("empty inventory must be an empty collection")
	}
}

func TestInventoryFailureDiscardsPartialResults(t *testing.T) {
	for _, variant := range []string{"nil-page", "api-error", "cycle", "long-token", "duplicate", "oversized-page", "bad-metadata"} {
		t.Run(variant, func(t *testing.T) {
			api := &statusAPI{read: func(_ context.Context, _ *sdk.DescribeInstanceInformationInput, call int) (*sdk.DescribeInstanceInformationOutput, error) {
				if call == 1 {
					return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{instanceInformation(1)}, NextToken: aws.String("synthetic-secret-token")}, nil
				}
				switch variant {
				case "nil-page":
					return nil, nil
				case "api-error":
					return nil, errors.New("synthetic-secret-api-error")
				case "cycle":
					return &sdk.DescribeInstanceInformationOutput{NextToken: aws.String("synthetic-secret-token")}, nil
				case "long-token":
					return &sdk.DescribeInstanceInformationOutput{NextToken: aws.String(strings.Repeat("x", 8193))}, nil
				case "duplicate":
					return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{instanceInformation(1)}}, nil
				case "oversized-page":
					return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: make([]types.InstanceInformation, 51)}, nil
				case "bad-metadata":
					info := instanceInformation(2)
					info.InstanceId = aws.String("synthetic-secret-invalid-id")
					return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{info}}, nil
				}
				return nil, nil
			}}
			rows, err := Inventory(context.Background(), api)
			if err == nil || rows != nil || api.calls != 2 || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatalf("partial results or metadata exposed: %v", err)
			}
		})
	}
}

func TestInventoryLimitsAndCancellation(t *testing.T) {
	for _, limit := range []string{"pages", "instances"} {
		api := &statusAPI{read: func(_ context.Context, _ *sdk.DescribeInstanceInformationInput, call int) (*sdk.DescribeInstanceInformationOutput, error) {
			out := &sdk.DescribeInstanceInformationOutput{NextToken: aws.String(fmt.Sprintf("page-%d", call))}
			if limit == "instances" {
				for i := 0; i < 50; i++ {
					out.InstanceInformationList = append(out.InstanceInformationList, instanceInformation((call-1)*50+i+1))
				}
			}
			return out, nil
		}}
		rows, err := Inventory(context.Background(), api)
		expected := 1000
		if limit == "instances" {
			expected = 201
		}
		if err == nil || rows != nil || api.calls != expected {
			t.Fatal("inventory limit ignored")
		}
	}
	for _, duringRead := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		api := &statusAPI{read: func(context.Context, *sdk.DescribeInstanceInformationInput, int) (*sdk.DescribeInstanceInformationOutput, error) {
			cancel()
			return &sdk.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{instanceInformation(1)}}, nil
		}}
		if !duringRead {
			cancel()
		}
		rows, err := Inventory(ctx, api)
		if !errors.Is(err, context.Canceled) || rows != nil || !duringRead && api.calls != 0 {
			t.Fatal("cancellation ignored")
		}
	}
	if rows, err := Inventory(context.Background(), nil); err == nil || rows != nil {
		t.Fatal("nil client accepted")
	}
}

func TestInventoryMetadataValidation(t *testing.T) {
	for _, mutate := range []func(*types.InstanceInformation){
		func(i *types.InstanceInformation) { i.InstanceId = nil },
		func(i *types.InstanceInformation) { i.InstanceId = aws.String("mi-0123456789abcdef0") },
		func(i *types.InstanceInformation) { i.InstanceId = aws.String("i-0123456789abcdef0\n") },
		func(i *types.InstanceInformation) { i.ResourceType = types.ResourceTypeManagedInstance },
		func(i *types.InstanceInformation) { i.ResourceType = "" },
		func(i *types.InstanceInformation) { i.PingStatus = "Online\x1b[2J" },
		func(i *types.InstanceInformation) { i.PingStatus = "" },
		func(i *types.InstanceInformation) { i.PlatformType = "unknown" },
		func(i *types.InstanceInformation) { i.PlatformType = "" },
		func(i *types.InstanceInformation) { i.AgentVersion = aws.String("3.3.0.0\n") },
		func(i *types.InstanceInformation) { i.AgentVersion = aws.String("3.3.0.0.1") },
		func(i *types.InstanceInformation) { i.AgentVersion = aws.String(strings.Repeat("1", 65536)) },
	} {
		info := instanceInformation(1)
		mutate(&info)
		if _, err := inventoryStatus(info); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	for _, ping := range []types.PingStatus{types.PingStatusOnline, types.PingStatusConnectionLost, types.PingStatusInactive} {
		for _, platform := range []types.PlatformType{types.PlatformTypeLinux, types.PlatformTypeWindows, types.PlatformTypeMacos} {
			info := instanceInformation(1)
			info.PingStatus, info.PlatformType, info.AgentVersion = ping, platform, nil
			row, err := inventoryStatus(info)
			if err != nil || row.PingStatus != ping || row.Platform != platform || row.AgentVersion != "" {
				t.Fatal("known values changed")
			}
		}
	}
}

func FuzzInventoryStatus(f *testing.F) {
	f.Add("i-0123456789abcdef0", "EC2Instance", "Online", "Linux", "3.3.0.0")
	f.Add("", "", "", "", "")
	f.Fuzz(func(t *testing.T, id, resource, ping, platform, version string) {
		_, _ = inventoryStatus(types.InstanceInformation{InstanceId: aws.String(id), ResourceType: types.ResourceType(resource), PingStatus: types.PingStatus(ping), PlatformType: types.PlatformType(platform), AgentVersion: aws.String(version)})
	})
}
