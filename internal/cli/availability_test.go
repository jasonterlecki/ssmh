package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	sdkssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/ssm"
)

type ambiguousAvailability struct {
	*cliAPI
	calls   int
	failure bool
}

func (a *ambiguousAvailability) DescribeInstanceInformation(context.Context, *sdkssm.DescribeInstanceInformationInput, ...func(*sdkssm.Options)) (*sdkssm.DescribeInstanceInformationOutput, error) {
	a.calls++
	if a.calls == 2 && a.failure {
		return nil, errors.New("synthetic-secret-response")
	}
	response := &sdkssm.DescribeInstanceInformationOutput{InstanceInformationList: []types.InstanceInformation{{InstanceId: sdkaws.String(cliTarget), ResourceType: types.ResourceTypeEc2Instance, PingStatus: types.PingStatusOnline, PlatformType: types.PlatformTypeLinux}}}
	if a.calls == 1 {
		response.NextToken = sdkaws.String("synthetic-secret-next-token")
	}
	return response, nil
}

func TestAvailabilityMustBeCompleteBeforeSessionCreation(t *testing.T) {
	for _, failure := range []bool{false, true} {
		in, out, stderr := cliFiles(t)
		api := &ambiguousAvailability{cliAPI: &cliAPI{}, failure: failure}
		d := cliDeps(api.cliAPI, &cliChannel{}, &idleClient{})
		d.client = func(sdkaws.Config) ssm.API { return api }
		err := run(context.Background(), []string{"-i", cliTarget, "--debug"}, in, out, stderr, d)
		if err == nil || api.calls != 2 || api.starts != 0 || api.terminates != 0 || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(cliText(t, stderr), "synthetic-secret") || cliText(t, out) != "" {
			t.Fatal("partial or ambiguous availability reached StartSession or leaked metadata")
		}
	}
}
