# AWS authentication

`ssmh` uses AWS SDK for Go v2, not SSH keys or an AWS CLI subprocess, to resolve
credentials. Native shells/commands/forwarding accept an EC2 ID or exact Name;
read-only discovery/checks are implemented. Plugin compatibility remains unfinished. Live AWS interoperability
has not been verified.

## Profiles and region

Use an organization-approved provider. The SDK supports environment credentials,
shared files, role profiles, IAM Identity Center, credential processes, web identity
and ECS/EC2 roles. SDK selection/refresh remain intact; the application does not
parse credential payloads. Shared files normally live at `~/.aws/config` and
`~/.aws/credentials`; `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` select
other files. See [SDK configuration](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html).

```sh
./bin/ssmh -i i-0123456789abcdef0 -p production -r ca-central-1
```

`--profile` selects an explicit shared profile. Otherwise the SDK uses its
environment/default selection, including `AWS_PROFILE`. This pinned SDK resolves
an explicit profile before its environment-credential branch: do not assume
exported access keys override `--profile`. Missing profiles and failed explicit
roles do not cause application fallback to another identity.

`--region` overrides SDK region selection; otherwise SDK environment/configuration
applies. An absent/invalid region is an error, never an invented default.
`--timeout` bounds setup, including credential resolution and MFA input (default
30s; positive durations up to 10m). A configured `credential_process` is executable
code the SDK may run: review it and protect configuration against other users'
modifications. Remote command text is never sent to that provider or a local shell.

## IAM Identity Center / SSO

Use your assigned account/permission set. Example shared **config**, with synthetic
values to replace:

```ini
[profile production]
region = ca-central-1
sso_session = company
sso_account_id = 123456789012
sso_role_name = RemoteAccess

[sso-session company]
sso_region = us-east-1
sso_start_url = https://example.awsapps.com/start
sso_registration_scopes = sso:account:access
```

The profile selects account/role; `sso-session` selects the portal and its region,
which can differ from the SSM region. Modern configuration supports refresh while
login remains valid; expired login requires reauthentication. Legacy configuration
lacks automatic token refresh. See [SSO settings](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sso-credentials.html).

If AWS CLI v2 is your chosen login tool, authenticate separately:

```sh
aws sso login --profile production
./bin/ssmh -i i-0123456789abcdef0 -p production -r ca-central-1
```

[`aws sso login`](https://docs.aws.amazon.com/cli/latest/reference/sso/login.html)
obtains/caches login material. It is a prerequisite example, not a command `ssmh`
invokes. AWS CLI is not required for native sessions once usable SDK credentials
exist. The application does not launch browser login or bypass expiration.

SDK-managed SSO refresh can rewrite the existing token cache under
`~/.aws/sso/cache`: the standard provider chain is not necessarily disk-free.
Protect cache/configuration/credential files with owner-only access; never commit
them or share their contents as diagnostics. The pinned SDK preserves existing
SSO cache permissions on refresh; `ssmh` does not repair unsafe permissions.
The SDK login-session provider may also refresh its own cache. The authentication
patch pins config v1.32.19/credentials v1.19.18 and `ssmh` explicitly requests
owner-only creation of new login cache files (0600 on Linux), even when
`AWS_RESTRICT_FILE_PERMISSIONS=unrestricted` is inherited. Existing file modes
are preserved, not repaired. This policy changes cache creation permissions,
not provider selection, login behavior or credential refresh. See the
[reviewed SDK login provider](https://github.com/aws/aws-sdk-go-v2/blob/74c501189a40c9b937432a1b2a4cacffc851ea76/credentials/logincreds/provider.go).
Application-owned configuration never stores credentials; explicitly assumed STS
credentials stay in memory. Go/SDK string erasure is not guaranteed. See the
[SDK token provider](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials/ssocreds#NewSSOTokenProvider).

## Explicit roles

`--arn` requests STS AssumeRole after base credentials resolve. Subsequent SSM and
identity calls use assumed credentials. The source needs authorization for that
exact role, its trust policy must permit the source, and the role needs the SSM
permissions in [the IAM guide](iam-policy.md). ExternalId/session names do not
grant permission; AWS authorization remains authoritative.

```sh
./bin/ssmh -i i-0123456789abcdef0 -p management -r ca-central-1 \
  --arn arn:aws:iam::123456789012:role/RemoteAccess \
  --session-name ssmh-investigation --external-id customer-reference
```

Supply ExternalId only for an approved role relationship. Session names appear
in AWS identity/audit information; never put secrets in them. An omitted name
becomes `ssmh-` plus a random identifier. Role options require `--arn`, not merely
a role profile. Profiles use their own SDK settings and may form a role chain
before an explicit `--arn`. See [STS semantics](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

SDK refresh remains enabled; failure fails closed with no return to base credentials,
role search or privilege escalation. No assumed credential file is written.
`--duration` limits the local SSM session, not STS lifetime or server-side policy.
Explicit roles use the SDK provider's default credential duration; no flag extends
it. Long sessions do not guarantee later AWS calls, including cleanup, can authenticate.

## MFA and unattended use

Prefer the controlling-terminal prompt over a command-line code:

```sh
./bin/ssmh -i i-0123456789abcdef0 -p management -r ca-central-1 \
  --arn arn:aws:iam::123456789012:role/RemoteAccess \
  --mfa-serial arn:aws:iam::123456789012:mfa/operator
```

Setup reads six digits from `/dev/tty` with echo disabled, never redirected stdin.
Full terminal settings are restored on controllable exits; queued input is cleared
before/after prompting so pasted codes do not become remote input. Ctrl+C cancels
setup. SDK role-profile MFA uses the same prompt. No controlling terminal means
prompting fails; unattended runs need approved noninteractive credentials.

`--mfa-token` requires `--mfa-serial` and is one-use for explicit role setup.
Process inspection/shell history can expose it; never put codes in scripts, logs
or repository files. Setup refresh requires a fresh code. Prompting permanently
ends before remote I/O and before cleanup after establishment failures. Later
refresh requiring MFA fails instead of consuming remote input. This may prevent
termination after expiration: cleanup is best effort and reports failure. Recover
authorization and use an approved AWS console/tool to terminate the specific
session if needed; do not terminate unrelated sessions.

## Safe troubleshooting

`--verbose` reports validated account/principal metadata, fixed provider labels
and stages; `--debug` adds bounded EC2/STS/SSM timings/retry counts. Labels are not
search history or proof of permission. Both add GetCallerIdentity and fail setup
if it fails; default/quiet do not add that request. See [diagnostics](diagnostics.md).

For credentials, check profile/file selection, login expiration and provider
availability. For roles, check source identity, trust, authorization and required
MFA/ExternalId. For session denial, separately review target/document/cleanup
permissions. Valid credentials or an Online agent do not exercise StartSession
permission. Errors omit raw SDK/provider output that may contain secrets.

Custom service endpoints and HTTP redirects are refused. TLS verification and
environment proxy support remain enabled. Optional `--ca-cert PATH` (alias `-ca`)
selects a PEM bundle using SDK WithCustomCABundle before credential-client setup.
Precedence is CLI, then `AWS_CA_BUNDLE`, then selected shared `ca_bundle`.
Omitting the option preserves SDK behavior. Relative paths and spaces are allowed;
quote paths containing spaces. Explicit empty paths, controls and paths exceeding
4096 bytes are refused. The CLI opens read-only/nonblocking, accepts only regular
files, limits reads to 4 MiB and closes before SDK loading. It never mutates the
environment or prints the path/file contents. Missing/unreadable/invalid bundles fail closed
with redacted errors. Explicit custom bundles replace system roots, following SDK
semantics: include every required CA, including the roots needed for AWS services.
Do not disable certificate or hostname verification. Environment/profile CA file
reads remain SDK-managed and not application-size-bounded; PEM parsing is SDK-owned.
Regular filesystem reads are not context-interruptible even for CLI paths; trust
the configured local file. A blocked filesystem can exceed the setup deadline.

Guards are installed before SDK resolution and retained by builder copies, so
custom CA support does not permit signed requests to new endpoints or redirects.
Captured SDK credential clients use HTTP/1.1 with keepalives disabled because their
builder copies expose no idle-pool cleanup API; refresh still uses the selected
SDK providers/cache. The returned application client has its own normally pooled
guarded transport, closed at operation end. Native sockets inherit its CA roots
and proxy settings. Tests use synthetic public CA files and in-memory TLS,
including rejection of untrusted roots/wrong hostnames before HTTP authentication
is sent; no live AWS/proxy validation is claimed.
