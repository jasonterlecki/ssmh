package ssm

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/config"
	"ssmh/internal/logging"
)

// Online verifies one exact EC2 registration without starting a session. It
// validates all returned pages before accepting a unique Online target and
// returns only allowlisted metadata, never a partial/raw SDK record on failure.
// Online status is not proof of EC2 state or StartSession authorization.
func Online(ctx context.Context, client StatusAPI, id string) (types.InstanceInformation, error) {
	if !config.InstanceID(id) || client == nil {
		return types.InstanceInformation{}, errors.New("SSM availability requires a valid EC2 instance ID and client")
	}
	input := &sdk.DescribeInstanceInformationInput{
		MaxResults: aws.Int32(inventoryPageSize),
		Filters:    []types.InstanceInformationStringFilter{{Key: aws.String("InstanceIds"), Values: []string{id}}},
	}
	seenTokens := map[string]bool{}
	var selected *Status
	for page := 0; page < inventoryPages; page++ {
		if err := ctx.Err(); err != nil {
			return types.InstanceInformation{}, err
		}
		response, err := client.DescribeInstanceInformation(ctx, input)
		if err != nil {
			return types.InstanceInformation{}, errors.Join(ctx.Err(), logging.Failure("check SSM availability", err))
		}
		if err := ctx.Err(); err != nil {
			return types.InstanceInformation{}, err
		}
		if response == nil || len(response.InstanceInformationList) > inventoryPageSize {
			return types.InstanceInformation{}, errors.New("SSM returned an invalid availability page")
		}
		for _, information := range response.InstanceInformationList {
			status, err := inventoryStatus(information)
			if err != nil || status.InstanceID != id || selected != nil {
				return types.InstanceInformation{}, errors.New("SSM returned invalid, unexpected or duplicate target metadata; retry if registration changed")
			}
			selected = &status
		}
		next := aws.ToString(response.NextToken)
		if next == "" {
			if selected == nil {
				return types.InstanceInformation{}, errors.New("instance is not registered with SSM; check agent and instance profile")
			}
			if selected.PingStatus != types.PingStatusOnline {
				return types.InstanceInformation{}, errors.New("SSM agent is not Online; check agent status and endpoint connectivity")
			}
			// Do not expose unrelated SDK Name/IP/hostname/association fields.
			result := types.InstanceInformation{InstanceId: aws.String(selected.InstanceID), ResourceType: types.ResourceTypeEc2Instance, PingStatus: selected.PingStatus, PlatformType: selected.Platform}
			if selected.AgentVersion != "" {
				result.AgentVersion = aws.String(selected.AgentVersion)
			}
			return result, nil
		}
		if len(next) > 8192 || seenTokens[next] {
			return types.InstanceInformation{}, errors.New("SSM returned invalid availability pagination data")
		}
		seenTokens[next] = true
		input.NextToken = aws.String(next)
	}
	return types.InstanceInformation{}, errors.New("SSM availability pagination exceeded its safety limit")
}
