package ec2

import (
	"context"
	"errors"
	"strings"

	"ssmh/internal/config"
)

// ErrNotFound means no exact target is visible to the selected EC2 identity.
var ErrNotFound = errors.New("no exact EC2 target found in the selected region; check instance ID or Name tag, account, region and ec2:DescribeInstances access")

// ErrAmbiguous means an exact Name identifies multiple instances. Use an ID;
// stopped/offline duplicates are not silently discarded to select another host.
var ErrAmbiguous = errors.New("multiple EC2 instances have that exact Name tag; specify an instance ID")

// Resolve reads every query page before accepting exactly one target. It does
// not check running state or SSM readiness; callers must do so before connecting.
func Resolve(ctx context.Context, client API, region, target string) (Instance, error) {
	if target == "" || !config.Text(target, 256) || strings.HasPrefix(target, "i-") && !config.InstanceID(target) {
		return Instance{}, errors.New("invalid EC2 instance ID or exact Name tag")
	}
	q := Query{Name: target}
	if config.InstanceID(target) {
		q = Query{InstanceID: target}
	}
	rows, err := Discover(ctx, client, region, q)
	if err != nil {
		return Instance{}, err
	}
	if len(rows) == 0 {
		return Instance{}, ErrNotFound
	}
	if len(rows) != 1 {
		return Instance{}, ErrAmbiguous
	}
	return rows[0], nil
}
