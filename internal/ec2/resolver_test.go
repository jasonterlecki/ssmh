package ec2

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestResolveExactNameAndID(t *testing.T) {
	for _, target := range []string{"prod", "i-00000000000000001", "prod*?", "生产"} {
		api := &mockAPI{read: func(_ context.Context, in *sdk.DescribeInstancesInput, call int) (*sdk.DescribeInstancesOutput, error) {
			if len(in.Filters) != 1 || len(in.InstanceIds) != 0 || aws.ToInt32(in.MaxResults) != 100 {
				t.Fatal("resolution query not bounded")
			}
			if call == 1 {
				return &sdk.DescribeInstancesOutput{NextToken: aws.String("next")}, nil
			}
			name := target
			if strings.HasPrefix(target, "i-") {
				name = "prod"
				if aws.ToString(in.Filters[0].Name) != "instance-id" {
					t.Fatal("ID used Name filter")
				}
			}
			return page(rawInstance(1, name)), nil
		}}
		row, err := Resolve(context.Background(), api, "ca-central-1", target)
		if err != nil || api.calls != 2 || row.ID != "i-00000000000000001" {
			t.Fatalf("exact resolution failed: %v", err)
		}
	}
}

func TestResolveNeverSelectsAmbiguousOrPartialTarget(t *testing.T) {
	for _, mode := range []string{"absent", "case", "duplicate name", "late error", "duplicate id"} {
		t.Run(mode, func(t *testing.T) {
			api := &mockAPI{read: func(_ context.Context, _ *sdk.DescribeInstancesInput, call int) (*sdk.DescribeInstancesOutput, error) {
				if mode == "absent" {
					return page(), nil
				}
				if mode == "case" {
					return page(rawInstance(1, "Prod")), nil
				}
				if call == 1 {
					p := page(rawInstance(1, "prod"))
					p.NextToken = aws.String("next")
					return p, nil
				}
				if mode == "late error" {
					return nil, errors.New("synthetic-secret")
				}
				id := 2
				if mode == "duplicate id" {
					id = 1
				}
				other := rawInstance(id, "prod")
				other.State.Name = types.InstanceStateNameStopped
				return page(other), nil
			}}
			row, err := Resolve(context.Background(), api, "ca-central-1", "prod")
			if err == nil || row != (Instance{}) || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("ambiguous/partial target accepted or error disclosed")
			}
			if mode == "absent" || mode == "case" {
				if !errors.Is(err, ErrNotFound) {
					t.Fatal("wrong absent error")
				}
			}
			if mode == "duplicate name" && !errors.Is(err, ErrAmbiguous) {
				t.Fatal("stopped duplicate silently discarded")
			}
		})
	}
	for _, target := range []string{"", "i-malformed", "bad\nname"} {
		api := &mockAPI{}
		if _, err := Resolve(context.Background(), api, "ca-central-1", target); err == nil || api.calls != 0 {
			t.Fatal("invalid target reached AWS")
		}
	}
}
