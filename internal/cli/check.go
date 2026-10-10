package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"ssmh/internal/aws"
	"ssmh/internal/config"
	"ssmh/internal/ec2"
	"ssmh/internal/logging"
	"ssmh/internal/ssm"
	"ssmh/internal/terminal"
)

type checkReport struct {
	Profile                    string  `json:"profile"`
	Account                    string  `json:"account_id,omitempty"`
	Identity                   string  `json:"identity_arn,omitempty"`
	IdentityStatus             string  `json:"identity_status"`
	Instance                   listRow `json:"instance"`
	Backend                    string  `json:"backend"`
	Document                   string  `json:"document"`
	Ready                      bool    `json:"ready"`
	SessionPermissionsVerified bool    `json:"session_permissions_verified"`
}

func check(ctx context.Context, o config.Options, output, stderr *os.File, d dependencies) (result error) {
	query := ec2.Query{InstanceID: o.Instance}
	if !config.InstanceID(o.Instance) {
		query = ec2.Query{Name: o.Instance}
	}
	if err := query.Validate(); err != nil {
		return usageError{err}
	}
	if ctx == nil || d.load == nil || d.identity == nil || d.ec2Client == nil || d.statusClient == nil || d.documentClient == nil {
		return errors.New("read-only check dependencies are unavailable")
	}
	setup, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	prompt := &mfaPrompt{ctx: setup, read: terminal.PromptMFA}
	defer prompt.close()
	diagnostic := diagnostics{writer: stderr, verbose: o.Verbose, debug: o.Debug}
	if o.Debug {
		setup, diagnostic.metrics = aws.WithAPIMetrics(setup)
	}
	if o.Verbose || o.Debug {
		stream, err := terminal.OpenStream(stderr, true)
		if err != nil {
			return errors.New("cannot initialize private diagnostic stream")
		}
		defer func() { result = errors.Join(result, stream.Close()) }()
		diagnostic.writer = &diagnosticWriter{stream: stream, ctx: setup}
	}
	started, err := diagnostic.begin(stageCredentials)
	if err != nil {
		return err
	}
	cfg, err := d.load(setup, o, prompt.token)
	if err == nil {
		defer aws.Close(cfg)
	}
	if err = diagnostic.end(stageCredentials, started, err); err != nil {
		return errors.Join(ctx.Err(), err)
	}
	if err := diagnostic.credentials(cfg); err != nil {
		return err
	}
	report := checkReport{Profile: o.Profile, Backend: "native", Document: "SSM-SessionManagerRunShell", IdentityStatus: "available"}
	started, err = diagnostic.begin(stageIdentity)
	if err != nil {
		return err
	}
	identity, identityErr := d.identity(setup, cfg)
	if errors.Is(identityErr, aws.ErrIdentityDenied) && setup.Err() == nil {
		// Metadata denial is not a different credential source or an auth fallback.
		// Every remaining authenticated API keeps the exact selected SDK config.
		report.IdentityStatus = "unavailable_access_denied"
		if err := errors.Join(diagnostic.emit(stageIdentity, "unavailable (access denied)", time.Since(started)), diagnostic.apiMetrics()); err != nil {
			return err
		}
	} else {
		if err := diagnostic.end(stageIdentity, started, identityErr); err != nil {
			return errors.Join(setup.Err(), err)
		}
		if identity.Account() == "" || identity.ARN() == "" {
			return errors.New("STS caller identity metadata is unavailable")
		}
		report.Account, report.Identity = identity.Account(), identity.ARN()
	}
	started, err = diagnostic.begin(stageDiscovery)
	if err != nil {
		return err
	}
	instance, err := ec2.Resolve(setup, d.ec2Client(cfg), cfg.Region, o.Instance)
	if err == nil && instance.State != "running" {
		err = errors.New("target EC2 instance is not running; check its state in the selected account and region")
	}
	if err = diagnostic.end(stageDiscovery, started, err); err != nil {
		return errors.Join(ctx.Err(), err)
	}
	started, err = diagnostic.begin(stageAvailability)
	if err != nil {
		return err
	}
	status, err := ssm.Online(setup, d.statusClient(cfg), instance.ID)
	if err == nil && status.PlatformType != types.PlatformTypeLinux {
		err = errors.New("native sessions require an SSM-managed Linux instance")
	}
	if err = diagnostic.end(stageAvailability, started, err); err != nil {
		return errors.Join(ctx.Err(), err)
	}
	started, err = diagnostic.begin(stageShellDocument)
	if err != nil {
		return err
	}
	err = ssm.ValidateShellDocument(setup, d.documentClient(cfg), "", cfg.Region)
	if err = diagnostic.end(stageShellDocument, started, err); err != nil {
		return errors.Join(ctx.Err(), err)
	}
	if err := setup.Err(); err != nil {
		return err
	}
	report.Instance = listRow{ID: instance.ID, Name: instance.Name, State: instance.State, SSM: string(status.PingStatus), Platform: string(status.PlatformType), PrivateIP: instance.PrivateIP, Region: instance.Region}
	report.Ready = true // Inspected prerequisites only, never authorization proof.
	prompt.close()
	data, err := formatCheck(report, o.JSON)
	if err != nil {
		return err
	}
	stream, err := terminal.OpenStream(output, true)
	if err != nil {
		return errors.New("cannot initialize private check output stream")
	}
	defer func() { result = errors.Join(result, stream.Close()) }()
	writeCtx, stopWrite := context.WithTimeout(setup, 10*time.Second)
	defer stopWrite()
	if err := stream.Write(writeCtx, data); err != nil {
		return errors.Join(writeCtx.Err(), errors.New("cannot write check output; discard any incomplete output"))
	}
	return setup.Err()
}

func formatCheck(report checkReport, machine bool) ([]byte, error) {
	if machine {
		return asciiJSON(report)
	}
	var output bytes.Buffer
	profile := logging.SafeText(report.Profile)
	if profile == "" {
		profile = "SDK provider chain (no explicit --profile)"
	}
	fmt.Fprintf(&output, "AWS Profile: %s\nAWS Region: %s\n", profile, report.Instance.Region)
	if report.IdentityStatus == "available" {
		fmt.Fprintf(&output, "AWS Account: %s\nIdentity: %s\n", report.Account, report.Identity)
	} else {
		fmt.Fprintln(&output, "Identity: unavailable (STS metadata access denied)")
	}
	fmt.Fprintf(&output, "Instance: %s\nName: %s\nInstance State: %s\nSSM Status: %s\nPlatform: %s\nPrivate IP: %s\nBackend: %s\nDocument: %s\n", report.Instance.ID, logging.SafeText(report.Instance.Name), report.Instance.State, report.Instance.SSM, report.Instance.Platform, report.Instance.PrivateIP, report.Backend, report.Document)
	fmt.Fprintln(&output, "Prerequisites passed. Session authorization and live data-channel connectivity are not verified.")
	return output.Bytes(), nil
}
