package ssm

import (
	"context"
	"errors"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/ssm"
	"ssmh/internal/config"
)

// StartForward starts one process-owned session using the exact AWS-managed
// forwarding document and explicit destination parameters. It never binds a
// local listener or substitutes a shell, SSH, custom document or default port.
// The caller must negotiate and validate a Port channel before serving traffic,
// and terminate the returned owned session even if subsequent setup fails.
func StartForward(ctx context.Context, client API, instance, region, reason string, target config.ForwardTarget) (*Session, error) {
	if ctx == nil || client == nil || !config.InstanceID(instance) || target.Validate() != nil || !config.Text(reason, 256) {
		return nil, errors.New("invalid forwarding session setup")
	}
	if err := config.Region(region); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	document := "AWS-StartPortForwardingSession"
	parameters := map[string][]string{
		"portNumber":      {strconv.Itoa(target.RemotePort)},
		"localPortNumber": {strconv.Itoa(target.LocalPort)},
	}
	if target.Host != "" {
		document = "AWS-StartPortForwardingSessionToRemoteHost"
		parameters["host"] = []string{target.Host}
	}
	request := &sdk.StartSessionInput{Target: aws.String(instance), DocumentName: aws.String(document), Parameters: parameters}
	if reason != "" {
		request.Reason = aws.String(reason)
	}
	// Start grants ownership only after a successful valid response. Do not drop
	// that returned ownership if cancellation races with the AWS response.
	return Start(ctx, client, request, region)
}
