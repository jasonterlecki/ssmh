# Troubleshooting the development client

Start with the selected region, profile, instance ID and operation. Never paste
AWS secrets, MFA codes, token-cache contents, signed stream URLs or raw request
dumps into logs or support reports. Errors intentionally omit raw SDK/provider
causes. `--verbose` reports fixed stages/validated identity; `--debug` adds bounded
API timings and native states, not packet or credential dumps. Neither is a proof
that all permissions have been exercised. See [diagnostic limits](diagnostics.md).

## Before authentication

`--backend plugin` remains unsupported and is refused before authentication.
Shell/command/forwarding accept an EC2 ID or exact case-sensitive Name. Multiple
exact Names require an ID, even if only one match is running; no fuzzy or
eligibility-based selection occurs. Installing a plugin or granting additional IAM
permissions does not complete the plugin backend. `auto` selects native only, with
no fallback. The CLI rejects conflicting session operations and forwarding with
`--document`; malformed arguments are not echoed into diagnostics.

`--list`/JSON is implemented read-only. It requires ec2:DescribeInstances and
ssm:DescribeInstanceInformation, defaults to running/SSM Online, and uses exact
case-sensitive Name/tag filters. Empty JSON success is `[]`; it can mean no visible
instances match those predicates, not that authorization to start a session was
tested. Do not broaden IAM or start permission-test sessions merely to obtain rows.
No partial API results are emitted. If stdout fails or times out, discard any
incomplete output and inspect the nonzero status. See [listing semantics](discovery.md).

`--check` is implemented for an ID or exact Name. It reads EC2 running, SSM
Linux/Online and the default shell document without starting a session. Ambiguous
Names require an ID; stopped/offline/non-Linux targets and invalid KMS preferences fail.
An explicit STS metadata denial is reported as unavailable, not another identity;
expired credentials, TLS/network errors and malformed metadata still fail.
The report does not prove StartSession permission or a live data channel. Do not
interpret JSON ready=true as session_permissions_verified=true. GetDocument is
needed for the same strict compatibility preflight as native shell setup.

A forwarding port conflict stops before AWS calls. Stop the process that owns
the requested port or explicitly choose another local port; the client never
silently chooses one. Permission failure does not cause sudo/elevation. Only
TCP4 `127.0.0.1` is supported. IPv6 remote literals need argument brackets:
`--forward-host 8080:[2001:db8::1]:80`. Do not weaken binding to expose a service.

## Credentials and explicit roles

Check the intended SDK profile/region selection and the organization's existing
login/credential refresh procedure. Missing/expired IAM Identity Center cache
requires a separate login; ssmh does not launch AWS CLI or bypass login. Inspect
configuration securely without printing secret fields or credential-process
output. A configured credential process is trusted local executable code, not a
remote command sent to the instance.

AssumeRole denial requires reviewing source permissions, the requested role's
trust/session policies and required ExternalId/MFA. Do not search for another
role or silently switch back to base credentials. MFA prompting needs `/dev/tty`,
never redirected stdin. Supply usable preauthenticated credentials for unattended
operation; do not put reusable secrets into command arguments. After setup,
refresh requiring another MFA prompt fails closed and can also prevent cleanup.
See [authentication and refresh limits](authentication.md).

## Online, authorization and documents

An Online prerequisite failure means complete SSM registration validation did not
succeed. Check the correct account/region/instance, agent health, instance profile
and endpoint connectivity through approved AWS operational tooling. Unexpected or
duplicate rows, malformed metadata and later pagination failures cannot be
ignored. Current native CLI paths require a Linux target. Every session first
requires a visible, uniquely resolved, running EC2 instance. Check account/region,
exact Name spelling and ec2:DescribeInstances access when resolution fails.
Online and running reports are not future-state or session-permission guarantees.

Access denial at document read, session start, data-channel setup or termination
is a distinct permission boundary. Review the exact target/document/owned-session
scope and applicable IAM/session/endpoint policies. A successful STS identity
lookup is not proof of StartSession authorization. Do not test permission by
starting an extra session unless deliberately authorized. The client never
modifies instance profiles, security groups or Session Manager preferences.
See [IAM guide](iam-policy.md).

Shell preflight requires recognized Standard_Stream preferences and a supported
literal KMS key matching region/partition, or no key. Expressions remain unsupported.
Unreadable/missing preferences fail closed. Command preflight requires a compatible
non-elevated document with separate output and unchanged command parameter;
the managed default may be incompatible. Use an explicitly reviewed document
that already meets those requirements, not a weaker client parser or implicit
Run Command/SSH alternative. Forwarding uses only its fixed AWS documents and a
strict matching Port handshake. See [commands](remote-commands.md) and
[forwarding](native-forwarding.md).

## TLS, proxies and channel establishment

For TLS failure, check system/custom CA trust, certificate validity/hostname,
the configured proxy and approved endpoint connectivity. AWS_CA_BUNDLE takes
precedence over shared ca_bundle and replaces system roots; missing/invalid
bundles fail closed without fallback. Include all required roots. Never use
insecure certificate verification or send credentials to a troubleshooting
endpoint. Custom service endpoints and HTTP redirects remain unsupported.

A native setup timeout can include authentication, document/API work and protocol
readiness, not merely a TCP connect. Increase `--timeout` deliberately if setup
needs more time; it does not repair denied authorization or malformed protocol.
A document-verified non-KMS shell with no initial output can time out. Required
unverified KMS actions, unsupported properties, mismatched destinations, invalid frames or
unexpected disconnects end setup/session rather than trigger a downgrade.

Native KMS shells now use authenticated document ownership, selected SDK config
and encrypted challenge. Check narrowly scoped kms:GenerateDataKey for the caller
and kms:Decrypt for the target, plus the selected key policy; no automatic grants
are made. Key mismatch, denied requests, canceled setup or failed challenge stop
the session without downgrade. Do not disable required KMS or weaken the agent's
challenge setting. Compatible command documents support literal KMS keys;
forwarding still refuses KMS and plugin launch is incomplete.
The [pinned KMS review](native-protocol.md#kms-shell-encryption-and-remaining-gates)
records the additional random-context challenge prerequisite for compatible
clients. A plugin minimum-version number alone does not prove policy compatibility.

Forwarding requires an agent version strictly greater than 3.1.1511.0 for the
reviewed multiplexing/no-keepalive path. The remote host is resolved/reached from
the instance. A global destination-error control cannot identify a failed stream,
so serving stops entirely; do not assume other connections remain usable. Tunnel
TLS to AWS does not replace application authentication/TLS to the destination.
No end-to-end independent TCP half-close is promised.

## Exit and cleanup

For a shell, physical Ctrl+C is remote input in raw mode; Enter then `~.` requests
local disconnect. For forwarding, Ctrl+C cancels locally; no raw mode/stdin reader
is used. `--duration` begins after successful StartSession and includes channel
setup. Local resources are shut down before fresh-context best-effort AWS cleanup.
Terminal restoration is attempted on controllable paths, not guaranteed after
SIGKILL/power loss. If the terminal is damaged after abrupt termination, use its
normal recovery procedure in a trusted local terminal, not a remote-output
instruction you have not verified.

Cleanup denial/timeout remains a visible failure even when the remote operation
succeeded. An authorized operator should inspect and clean up the exact owned
session through approved AWS tooling; never terminate unrelated sessions. This
client does not list sessions or persist a cleanup credential/token file.
Command status is known only with valid typed status, owned EOF, delivered output
and successful cleanup; interruption or missing status is not remote success.

The earlier sandbox denied OS sockets/module downloads. User-enabled network
access now permits normal EC2 SDK acquisition; the previous denials do not prove
host DNS is broken or live AWS connectivity passed. Never bypass production
security to troubleshoot connectivity. Go tests/builds
and synthetic TLS fixtures are useful evidence but not live AWS validation.
