package ec2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

type mockAPI struct {
	calls int
	read  func(context.Context, *sdk.DescribeInstancesInput, int) (*sdk.DescribeInstancesOutput, error)
}

func (m *mockAPI) DescribeInstances(ctx context.Context, in *sdk.DescribeInstancesInput, _ ...func(*sdk.Options)) (*sdk.DescribeInstancesOutput, error) {
	m.calls++
	return m.read(ctx, in, m.calls)
}

func rawInstance(n int, name string) types.Instance {
	return types.Instance{InstanceId: aws.String(fmt.Sprintf("i-%017x", n)), State: &types.InstanceState{Name: types.InstanceStateNameRunning}, PrivateIpAddress: aws.String("10.0.0.10"), Tags: []types.Tag{{Key: aws.String("Name"), Value: aws.String(name)}}}
}

func page(items ...types.Instance) *sdk.DescribeInstancesOutput {
	return &sdk.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: items}}}
}

func TestDiscoverPaginationAndExactPredicates(t *testing.T) {
	q := Query{Name: `prod*?\`, State: "running", Tags: []string{`Environment=Production`, `Empty=`}}
	api := &mockAPI{read: func(ctx context.Context, in *sdk.DescribeInstancesInput, call int) (*sdk.DescribeInstancesOutput, error) {
		want := []types.Filter{
			{Name: aws.String("tag:Name"), Values: []string{`prod\*\?\\`}},
			{Name: aws.String("instance-state-name"), Values: []string{"running"}},
			{Name: aws.String("tag:Environment"), Values: []string{"Production"}},
			{Name: aws.String("tag:Empty"), Values: []string{""}},
		}
		if ctx.Err() != nil || aws.ToInt32(in.MaxResults) != 100 || len(in.InstanceIds) != 0 || in.DryRun != nil || !reflect.DeepEqual(in.Filters, want) {
			t.Fatal("query changed")
		}
		if call == 1 {
			if in.NextToken != nil {
				t.Fatal("first page has token")
			}
			return &sdk.DescribeInstancesOutput{NextToken: aws.String("opaque-two")}, nil
		}
		if call != 2 || aws.ToString(in.NextToken) != "opaque-two" {
			t.Fatal("empty page not followed")
		}
		a, b, wrong := rawInstance(2, q.Name), rawInstance(1, q.Name), rawInstance(3, "production")
		for _, item := range []*types.Instance{&a, &b, &wrong} {
			item.Tags = append(item.Tags, types.Tag{Key: aws.String("Environment"), Value: aws.String("Production")}, types.Tag{Key: aws.String("Empty"), Value: aws.String("")})
		}
		stopped := rawInstance(4, q.Name)
		stopped.State.Name = types.InstanceStateNameStopped
		missing := rawInstance(5, q.Name)
		return page(a, wrong, stopped, missing, b), nil
	}}
	rows, err := Discover(context.Background(), api, "ca-central-1", q)
	if err != nil || api.calls != 2 || len(rows) != 2 || rows[0].ID != "i-00000000000000001" || rows[1].ID != "i-00000000000000002" || rows[0].Name != q.Name || rows[0].Region != "ca-central-1" || rows[0].PrivateIP != "10.0.0.10" {
		t.Fatalf("wrong sorted/exact results: %v %v", rows, err)
	}
}

func TestDiscoverInvalidQueriesBeforeAPI(t *testing.T) {
	queries := []Query{{InstanceID: "i-bad"}, {Name: "bad\nname"}, {Name: strings.Repeat("a", 257)}, {State: "unknown"}, {Tags: []string{"broken"}}, {Tags: []string{"=value"}}, {Tags: []string{"key=value", "key=other"}}, {Tags: []string{"Name=a"}, Name: "b"}, {Tags: []string{"key=bad\x1b"}}, {Tags: make([]string, 51)}}
	many := Query{Name: "a", State: "running"}
	for i := 0; i < 49; i++ {
		many.Tags = append(many.Tags, fmt.Sprintf("key%d=v", i))
	}
	queries = append(queries, many)
	queries = append(queries, Query{Name: strings.Repeat("*", 128)}, Query{Name: strings.Repeat("a", 256)}, Query{Tags: []string{"key=" + strings.Repeat("?", 128)}})
	for _, q := range queries {
		api := &mockAPI{read: func(context.Context, *sdk.DescribeInstancesInput, int) (*sdk.DescribeInstancesOutput, error) {
			t.Fatal("invalid query reached API")
			return nil, nil
		}}
		if rows, err := Discover(context.Background(), api, "ca-central-1", q); err == nil || rows != nil || api.calls != 0 {
			t.Fatal("invalid query accepted")
		}
	}
	api := &mockAPI{}
	for _, region := range []string{"", "bad\nregion"} {
		if _, err := Discover(context.Background(), api, region, Query{}); err == nil {
			t.Fatal("invalid region accepted")
		}
	}
	if _, err := Discover(nil, api, "ca-central-1", Query{}); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := Discover(context.Background(), nil, "ca-central-1", Query{}); err == nil {
		t.Fatal("nil client accepted")
	}
}

func TestDiscoverMalformedMetadataDiscardsAll(t *testing.T) {
	cases := map[string]func(*types.Instance){
		"id":            func(i *types.Instance) { i.InstanceId = aws.String("synthetic-secret") },
		"nil state":     func(i *types.Instance) { i.State = nil },
		"unknown state": func(i *types.Instance) { i.State.Name = "synthetic-secret" },
		"address":       func(i *types.Instance) { i.PrivateIpAddress = aws.String("synthetic-secret") },
		"ipv6":          func(i *types.Instance) { i.PrivateIpAddress = aws.String("::1") },
		"mapped":        func(i *types.Instance) { i.PrivateIpAddress = aws.String("::ffff:10.0.0.1") },
		"nil key":       func(i *types.Instance) { i.Tags[0].Key = nil },
		"nil value":     func(i *types.Instance) { i.Tags[0].Value = nil },
		"controls":      func(i *types.Instance) { i.Tags[0].Value = aws.String("synthetic-secret\x1b[31m") },
		"utf8":          func(i *types.Instance) { i.Tags[0].Value = aws.String("\xff") },
		"long":          func(i *types.Instance) { i.Tags[0].Value = aws.String(strings.Repeat("x", 257)) },
		"duplicate tag": func(i *types.Instance) { i.Tags = append(i.Tags, i.Tags[0]) },
		"too many tags": func(i *types.Instance) { i.Tags = make([]types.Tag, 51) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			api := &mockAPI{read: func(_ context.Context, _ *sdk.DescribeInstancesInput, call int) (*sdk.DescribeInstancesOutput, error) {
				if call == 1 {
					p := page(rawInstance(1, "good"))
					p.NextToken = aws.String("next")
					return p, nil
				}
				i := rawInstance(2, "good")
				change(&i)
				return page(i), nil
			}}
			rows, err := Discover(context.Background(), api, "ca-central-1", Query{})
			if err == nil || rows != nil || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("malformed metadata retained or disclosed")
			}
		})
	}
}

func TestDiscoverBoundsAndLaterErrors(t *testing.T) {
	for _, mode := range []string{"nil", "duplicate", "cycle", "long token", "pages", "instances", "reservations", "total", "error", "unexpected id"} {
		t.Run(mode, func(t *testing.T) {
			api := &mockAPI{read: func(_ context.Context, _ *sdk.DescribeInstancesInput, call int) (*sdk.DescribeInstancesOutput, error) {
				p := page(rawInstance(call, "name"))
				switch mode {
				case "nil":
					return nil, nil
				case "duplicate":
					p = page(rawInstance(1, "name"), rawInstance(1, "name"))
				case "cycle":
					p.NextToken = aws.String("same")
				case "long token":
					p.NextToken = aws.String(strings.Repeat("t", 8193))
				case "pages":
					p = &sdk.DescribeInstancesOutput{NextToken: aws.String(fmt.Sprint(call))}
				case "instances":
					p.Reservations[0].Instances = make([]types.Instance, maxPageItems+1)
				case "reservations":
					p.Reservations = make([]types.Reservation, maxPageItems+1)
				case "total":
					items := make([]types.Instance, maxPageItems)
					for n := range items {
						items[n] = rawInstance((call-1)*maxPageItems+n+1, "name")
					}
					p = page(items...)
					p.NextToken = aws.String(fmt.Sprint(call))
				case "error":
					if call == 2 {
						return nil, &smithy.GenericAPIError{Code: "UnauthorizedOperation", Message: "synthetic-secret"}
					}
					p.NextToken = aws.String("next")
				}
				return p, nil
			}}
			q := Query{}
			if mode == "unexpected id" {
				q.InstanceID = "i-00000000000000002"
			}
			rows, err := Discover(context.Background(), api, "ca-central-1", q)
			if err == nil || rows != nil || strings.Contains(err.Error(), "synthetic-secret") || api.calls > maxPages {
				t.Fatalf("limit or redaction failed: %v", err)
			}
			if mode == "error" && !strings.Contains(err.Error(), "access denied") {
				t.Fatal("permission error not actionable")
			}
		})
	}
}

func TestDiscoverCancellationAndEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	api := &mockAPI{}
	if rows, err := Discover(ctx, api, "ca-central-1", Query{}); !errors.Is(err, context.Canceled) || rows != nil || api.calls != 0 {
		t.Fatal("pre-call cancellation ignored")
	}
	ctx, cancel = context.WithCancel(context.Background())
	api.read = func(context.Context, *sdk.DescribeInstancesInput, int) (*sdk.DescribeInstancesOutput, error) {
		cancel()
		return page(rawInstance(1, "name")), nil
	}
	if rows, err := Discover(ctx, api, "ca-central-1", Query{}); !errors.Is(err, context.Canceled) || rows != nil {
		t.Fatal("post-call cancellation ignored")
	}
	api.read = func(context.Context, *sdk.DescribeInstancesInput, int) (*sdk.DescribeInstancesOutput, error) {
		return &sdk.DescribeInstancesOutput{}, nil
	}
	if rows, err := Discover(context.Background(), api, "ca-central-1", Query{}); err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("empty inventory not successful collection")
	}
	i := rawInstance(1, "")
	i.PrivateIpAddress = nil
	i.Tags = nil
	api.read = func(context.Context, *sdk.DescribeInstancesInput, int) (*sdk.DescribeInstancesOutput, error) {
		return page(i), nil
	}
	if rows, err := Discover(context.Background(), api, "ca-central-1", Query{}); err != nil || len(rows) != 1 || rows[0].Name != "" || rows[0].PrivateIP != "" {
		t.Fatal("optional metadata incorrectly required")
	}
}

type inventoryHTTP func(*http.Request) (*http.Response, error)

func (f inventoryHTTP) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestDiscoverThroughSignedSDK(t *testing.T) {
	calls := 0
	client := sdk.NewFromConfig(aws.Config{Region: "ca-central-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", ""), HTTPClient: inventoryHTTP(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Scheme != "https" || r.URL.Host != "ec2.ca-central-1.amazonaws.com" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatal("SDK request not authenticated regional EC2")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		q, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		if q.Get("Action") != "DescribeInstances" || q.Get("Version") != "2016-11-15" || q.Get("MaxResults") != "100" || q.Get("Filter.1.Name") != "tag:Name" || q.Get("Filter.1.Value.1") != `prod\*` || q.Get("InstanceId.1") != "" || q.Get("DryRun") != "" {
			t.Fatal("SDK query serialization changed")
		}
		response := `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>synthetic</requestId><reservationSet/><nextToken>opaque-next</nextToken></DescribeInstancesResponse>`
		if calls == 1 {
			if q.Get("NextToken") != "" {
				t.Fatal("initial token supplied")
			}
		} else {
			if calls != 2 || q.Get("NextToken") != "opaque-next" {
				t.Fatal("SDK pagination changed")
			}
			response = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>synthetic</requestId><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><code>16</code><name>running</name></instanceState><privateIpAddress>10.0.0.10</privateIpAddress><tagSet><item><key>Name</key><value>prod*</value></item></tagSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(response)), Request: r}, nil
	})})
	rows, err := Discover(context.Background(), client, "ca-central-1", Query{Name: "prod*"})
	if err != nil || calls != 2 || len(rows) != 1 || rows[0].ID != "i-0123456789abcdef0" || rows[0].Name != "prod*" {
		t.Fatalf("signed SDK XML fixture failed: %v", err)
	}
}
