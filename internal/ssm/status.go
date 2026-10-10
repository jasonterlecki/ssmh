package ssm

import (
	"context"
	"errors"
	"regexp"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/config"
	"ssmh/internal/logging"
)

// StatusAPI is the read-only SSM inventory boundary. No session can be started
// or terminated through it.
type StatusAPI interface {
	DescribeInstanceInformation(context.Context, *sdk.DescribeInstanceInformationInput, ...func(*sdk.Options)) (*sdk.DescribeInstanceInformationOutput, error)
}

// Status contains only validated availability metadata for one EC2 instance.
// Online is an agent report, not proof of EC2 state or StartSession permission.
// EC2 names and private addresses must come from the EC2 discovery boundary.
type Status struct {
	InstanceID   string
	PingStatus   types.PingStatus
	Platform     types.PlatformType
	AgentVersion string
}

const (
	inventoryPageSize = 50
	inventoryPages    = 1000
	inventoryItems    = 10000
)

var agentVersion = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,6}){2,3}$`)

// Inventory reads EC2 SSM registration without executing any remote operation.
// It returns a sorted complete result or an error with no partial inventory.
// Pagination, response sizes, duplicate IDs and known status/platform values are
// checked. This API is not a consistent snapshot; concurrent inventory changes
// can yield a duplicate-ID error, in which case the caller may explicitly retry.
func Inventory(ctx context.Context, client StatusAPI) ([]Status, error) {
	if client == nil {
		return nil, errors.New("SSM inventory client is unavailable")
	}
	input := &sdk.DescribeInstanceInformationInput{
		MaxResults: aws.Int32(inventoryPageSize),
		Filters:    []types.InstanceInformationStringFilter{{Key: aws.String("ResourceType"), Values: []string{string(types.ResourceTypeEc2Instance)}}},
	}
	seenTokens, seenIDs := map[string]bool{}, map[string]bool{}
	result := make([]Status, 0)
	for page := 0; page < inventoryPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := client.DescribeInstanceInformation(ctx, input)
		if err != nil {
			return nil, errors.Join(ctx.Err(), logging.Failure("read SSM inventory", err))
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if response == nil || len(response.InstanceInformationList) > inventoryPageSize {
			return nil, errors.New("SSM returned an invalid inventory page")
		}
		if len(result)+len(response.InstanceInformationList) > inventoryItems {
			return nil, errors.New("SSM inventory exceeds the 10000-instance safety limit; incomplete results were discarded")
		}
		for _, information := range response.InstanceInformationList {
			status, err := inventoryStatus(information)
			if err != nil || seenIDs[status.InstanceID] {
				return nil, errors.New("SSM returned invalid or duplicate EC2 inventory metadata; retry if inventory changed")
			}
			seenIDs[status.InstanceID] = true
			result = append(result, status)
		}
		next := aws.ToString(response.NextToken)
		if next == "" {
			sort.Slice(result, func(i, j int) bool { return result[i].InstanceID < result[j].InstanceID })
			return result, nil
		}
		if len(next) > 8192 || seenTokens[next] {
			return nil, errors.New("SSM returned invalid inventory pagination data")
		}
		seenTokens[next] = true
		input.NextToken = aws.String(next)
	}
	return nil, errors.New("SSM inventory pagination exceeded its safety limit")
}

func inventoryStatus(information types.InstanceInformation) (Status, error) {
	invalid := errors.New("invalid SSM EC2 availability metadata")
	status := Status{InstanceID: aws.ToString(information.InstanceId), PingStatus: information.PingStatus, Platform: information.PlatformType, AgentVersion: aws.ToString(information.AgentVersion)}
	if !config.InstanceID(status.InstanceID) || information.ResourceType != types.ResourceTypeEc2Instance {
		return Status{}, invalid
	}
	switch status.PingStatus {
	case types.PingStatusOnline, types.PingStatusConnectionLost, types.PingStatusInactive:
	default:
		return Status{}, invalid
	}
	switch status.Platform {
	case types.PlatformTypeLinux, types.PlatformTypeWindows, types.PlatformTypeMacos:
	default:
		return Status{}, invalid
	}
	if status.AgentVersion != "" && !agentVersion.MatchString(status.AgentVersion) {
		return Status{}, invalid
	}
	return status, nil
}
