// Package ec2 provides read-only, bounded EC2 target discovery through SDK v2.
package ec2

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"ssmh/internal/config"
	"ssmh/internal/logging"
)

// API is the read-only SDK boundary; it cannot create or modify resources.
type API interface {
	DescribeInstances(context.Context, *sdk.DescribeInstancesInput, ...func(*sdk.Options)) (*sdk.DescribeInstancesOutput, error)
}

// Instance retains only validated EC2 metadata. Name is untrusted display text;
// callers must sanitize it for terminal output even after validation here.
// PrivateIP may be empty, including for IPv6-only or terminated instances.
type Instance struct {
	ID, Name, State, PrivateIP, Region string
}

// Query specifies exact, case-sensitive predicates combined with AND. Tags use
// KEY=VALUE syntax, with one value per key. An empty query lists all EC2 states.
type Query struct {
	InstanceID, Name, State string
	Tags                    []string
}

const (
	pageSize     = 100
	maxPages     = 1000
	maxItems     = 10000
	maxPageItems = 1000
)

var literalFilter = strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`)

// Validate checks exact-query syntax and AWS filter limits before authentication.
func (q Query) Validate() error {
	_, _, err := q.filters()
	return err
}

func validState(state string) bool {
	switch state {
	case "pending", "running", "shutting-down", "terminated", "stopping", "stopped":
		return true
	}
	return false
}

func (q Query) filters() ([]types.Filter, map[string]string, error) {
	invalid := errors.New("invalid EC2 discovery filters; use exact Name, state and unique KEY=VALUE tags (at most 50 total filters)")
	if q.InstanceID != "" && !config.InstanceID(q.InstanceID) || !config.Text(q.Name, 256) || q.State != "" && !validState(q.State) || len(q.Tags) > 50 {
		return nil, nil, invalid
	}
	filters := make([]types.Filter, 0, len(q.Tags)+3)
	add := func(key, value string) {
		filters = append(filters, types.Filter{Name: aws.String(key), Values: []string{literalFilter.Replace(value)}})
	}
	if q.InstanceID != "" {
		add("instance-id", q.InstanceID)
	}
	if q.Name != "" {
		add("tag:Name", q.Name)
	}
	if q.State != "" {
		add("instance-state-name", q.State)
	}
	tags := make(map[string]string, len(q.Tags))
	for _, tag := range q.Tags {
		key, value, ok := strings.Cut(tag, "=")
		_, duplicate := tags[key]
		if !ok || key == "" || !config.Text(key, 128) || !config.Text(value, 256) || duplicate || key == "Name" && q.Name != "" {
			return nil, nil, invalid
		}
		tags[key] = value
		add("tag:"+key, value)
	}
	if len(filters) > 50 {
		return nil, nil, invalid
	}
	for _, filter := range filters {
		if utf8.RuneCountInString(filter.Values[0]) > 255 {
			return nil, nil, errors.New("EC2 filter value exceeds 255 characters after literal wildcard escaping")
		}
	}
	return filters, tags, nil
}

// Discover returns a complete sorted collection or an error with no partial
// result. It uses the supplied client's selected identity and endpoint; region
// labels must match that client. It never starts a session or proves permission
// to do so. Bounds apply after SDK decoding, not to HTTP response allocation.
func Discover(ctx context.Context, client API, region string, q Query) ([]Instance, error) {
	if ctx == nil || client == nil {
		return nil, errors.New("EC2 discovery context or client is unavailable")
	}
	if err := config.Region(region); err != nil {
		return nil, err
	}
	filters, tags, err := q.filters()
	if err != nil {
		return nil, err
	}
	input := &sdk.DescribeInstancesInput{MaxResults: aws.Int32(pageSize), Filters: filters}
	seenTokens, seenIDs := map[string]bool{}, map[string]bool{}
	rows := make([]Instance, 0)
	total := 0
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out, err := client.DescribeInstances(ctx, input)
		if err != nil {
			return nil, errors.Join(ctx.Err(), logging.Failure("read EC2 inventory", err))
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if out == nil || len(out.Reservations) > maxPageItems {
			return nil, errors.New("EC2 returned an invalid inventory page")
		}
		pageItems := 0
		for _, reservation := range out.Reservations {
			if len(reservation.Instances) > maxPageItems-pageItems {
				return nil, errors.New("EC2 inventory page exceeds its safety limit")
			}
			pageItems += len(reservation.Instances)
		}
		if pageItems > maxItems-total {
			return nil, errors.New("EC2 inventory exceeds the 10000-instance safety limit; incomplete results were discarded")
		}
		total += pageItems
		for _, reservation := range out.Reservations {
			for _, raw := range reservation.Instances {
				row, metadata, err := instance(raw, region)
				if err != nil || seenIDs[row.ID] {
					return nil, errors.New("EC2 returned invalid or duplicate instance metadata; retry if inventory changed")
				}
				seenIDs[row.ID] = true
				if q.InstanceID != "" && row.ID != q.InstanceID {
					return nil, errors.New("EC2 returned an unexpected target instance")
				}
				if q.Name != "" && row.Name != q.Name || q.State != "" && row.State != q.State {
					continue
				}
				matches := true
				for key, value := range tags {
					if actual, ok := metadata[key]; !ok || actual != value {
						matches = false
						break
					}
				}
				if matches {
					rows = append(rows, row)
				}
			}
		}
		next := aws.ToString(out.NextToken)
		if next == "" {
			sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
			return rows, nil
		}
		if len(next) > 8192 || seenTokens[next] {
			return nil, errors.New("EC2 returned invalid inventory pagination data")
		}
		seenTokens[next] = true
		input.NextToken = aws.String(next)
	}
	return nil, errors.New("EC2 inventory pagination exceeded its safety limit")
}

func instance(raw types.Instance, region string) (Instance, map[string]string, error) {
	invalid := errors.New("invalid EC2 instance metadata")
	row := Instance{ID: aws.ToString(raw.InstanceId), PrivateIP: aws.ToString(raw.PrivateIpAddress), Region: region}
	if !config.InstanceID(row.ID) || raw.State == nil || !validState(string(raw.State.Name)) || len(raw.Tags) > 50 {
		return Instance{}, nil, invalid
	}
	row.State = string(raw.State.Name)
	if row.PrivateIP != "" {
		ip, err := netip.ParseAddr(row.PrivateIP)
		if err != nil || !ip.Is4() || ip.String() != row.PrivateIP {
			return Instance{}, nil, invalid
		}
	}
	tags := make(map[string]string, len(raw.Tags))
	for _, tag := range raw.Tags {
		key, value := aws.ToString(tag.Key), aws.ToString(tag.Value)
		_, duplicate := tags[key]
		if tag.Key == nil || tag.Value == nil || key == "" || !config.Text(key, 128) || !config.Text(value, 256) || duplicate {
			return Instance{}, nil, invalid
		}
		tags[key] = value
	}
	row.Name = tags["Name"]
	return row, tags, nil
}
