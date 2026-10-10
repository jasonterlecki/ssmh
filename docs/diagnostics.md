# Connection diagnostics

Default output is minimal and uses stderr. `--quiet` suppresses informational
messages, never errors. `--verbose` and `--debug` are incompatible with quiet.
Help/version and unsupported modes do not authenticate or query identity.
Native forwarding reports its listening address and exact destination after
validated Port readiness, with bounded private stderr writes even in default
mode. It does not print application traffic or read stdin. Quiet suppresses this
information; errors and cleanup failures remain visible. Binding precedes SDK
loading, so port conflicts do not query AWS. Forwarding uses the same opt-in
identity/metrics/stage rules below, not extra default STS calls.

Verbose/debug session and list setup performs a read-only
[STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
request using the already selected SDK configuration, including an explicitly
assumed role. It shares `--timeout` with other establishment operations. Only
validated account/principal ARN metadata is retained and displayed; STS UserId
is not retained. Identity errors stop setup, are redacted, and never cause a
different credential source to be tried. Default/quiet session and list modes
make no added identity request. Read-only `--check` always queries identity,
including in quiet mode. Only explicit STS metadata AccessDenied may yield
`unavailable_access_denied` while remaining checks use exactly the same selected
configuration; expired/invalid credentials, malformed identity, other failures
and cancellation still fail. This is not authentication fallback. Caller
identity does not prove StartSession authorization.
Account and ARN account must match; only IAM/STS principal types are accepted.
Printable ASCII IAM paths follow the documented
[IAM path/name rules](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html),
including path punctuation, while terminal controls and malformed subjects fail.

Fixed lifecycle stages report authentication, identity, EC2 discovery, SSM availability,
document validation/session creation, channel establishment, remote operation,
and owned-session cleanup. Debug adds nonnegative elapsed milliseconds for each
completed/failed stage. These durations can include multiple SDK calls/retries.
Debug also reports individual allowlisted SDK operation summaries as described
below, plus fixed native transport states.

Verbose/debug additionally report one fixed local termination reason after the
owned AWS cleanup attempt: local cancellation requested, caller deadline exceeded,
local duration limit reached, session setup failed, operation/reporting failed,
or operation returned successfully (remote completion or local disconnect).
The lifetime error is snapshotted before the client's own deferred cancellation,
so ordinary shutdown is not mislabeled as expiration/caller cancellation. The
caller error is snapshotted before cleanup, which can outlive that context; a
cancellation arriving during TerminateSession does not rewrite the earlier cause. No
signal number, remote exit text, command/reason string or raw error is inspected
or printed. Cancellation/expiry indicates local evidence, not the sole cause of
an independent failure. An operation return does not prove remote completion or
successful AWS termination; cleanup has its own completed/failed stage and any
cleanup/reporting error still affects the result. Default/quiet remain unchanged.

## Native transport states

Debug attaches a bounded state collector to the native lifetime context; default,
quiet and verbose do not attach one. Fixed labels report WebSocket opening,
successful TLS/upgrade with token submission, establishment failure, pending
protocol readiness, verified handshake or document-authorized first shell output,
publication pause/resume, retransmission attempts, owned-session EOF, cancellation,
failure and socket closure/close failure. Token submission is not a separate
server acknowledgement; protocol readiness is reported only after its existing
validation. Socket closure does not establish AWS TerminateSession success.

Each event contains only its fixed label and nonnegative `since_trace_ms`, measured
from collector creation before Connect, not an operation duration. There are no
frame payloads, bytes/counts, sequence numbers, UUIDs, session identifiers, URLs,
headers, CustomerMessage text, tokens or raw errors. Observation changes no
protocol/retry/ownership decisions and performs no I/O in the network loop.

At most 64 events await draining; further events are dropped with an omission
notice. CLI drains at stage boundaries, so session-time transitions appear when
the remote operation ends, not synchronously with terminal traffic. Events after
a drain can appear in the next one; this is not a persistent audit log. Reporting
uses the same bounded private writer and failure/owned-cleanup rules as API
summaries. More detailed protocol diagnostics and safe CustomerMessage presentation
remain unfinished; raw message dumps are intentionally unavailable.

## Credential-source labels

Verbose/debug read the selected SDK provider's public
[numeric source metadata](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#CredentialProviderSource),
including through its credential cache. This observation makes no additional
Retrieve call and does not read credential values or the arbitrary credential
Source string. Only fixed labels are emitted: environment, shared/source profile,
profile credential source, IAM Identity Center (including legacy), web identity,
STS AssumeRole/SAML/federation/session token, credential process, HTTP credentials
endpoint, EC2 instance metadata, login cache, or in-process/static.

At most 32 metadata entries are inspected; repeated labels are deduplicated in
reported order. Missing, oversized or unknown metadata yields `unavailable`, not
partial classification, an authentication failure or a different provider. Default
and quiet modes do not inspect this metadata. Reporting errors stop setup before
identity or session requests.

These are SDK-reported sources, not a search/refresh history or proof of
authorization. Explicit `--arn` reports the final STS AssumeRole provider; the
client does not invent a base-provider breadcrumb. HTTP metadata does not establish
that a provider is ECS, and in-process/static does not establish that credentials
were hardcoded. No profile path, endpoint, raw provider object or secret is printed.

## SDK operation summaries

Debug alone installs observation through the SDK's
[APIOptions middleware boundary](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/middleware.html).
The recorder sits at the end of Initialize and observes the downstream operation:
serialization, authentication, SDK retries/backoff, transport and response
decoding. It does not time earlier Initialize middleware or external credential
process/IMDS work. Labels are restricted to EC2 DescribeInstances, STS
AssumeRole/GetCallerIdentity and SSM
DescribeInstanceInformation/GetDocument/StartSession/TerminateSession, plus KMS
GenerateDataKey for document-owned encrypted shells/commands. KMS key references,
encryption context, plaintext and ciphertext never enter summaries; the selected
debug collector is retained even when key preparation uses a child context.
Every paginated SDK call has its own summary; the EC2 discovery stage covers the
complete resolver/inventory instead. Filters, tag Names, instance IDs, pagination
tokens, request IDs and EC2 response fields never enter summaries.
Unknown service/operation pairs produce no summary, never arbitrary label text.
No instrumentation is installed for default/quiet/verbose clients.

Each summary contains only fixed service/operation labels, completed/failed,
nonnegative elapsed milliseconds and retry-loop attempt/retry counts from
[SDK attempt metadata](https://github.com/aws/aws-sdk-go-v2/blob/v1.41.9/aws/retry/metadata.go).
Missing metadata is reported as `attempts=unavailable`, not an invented zero.
Attempts are not HTTP transmission counts: validation or cancellation can stop a
retry-loop entry before a request is sent. Retries are additional loop entries
after the first. Timings include backoff and can overlap when an SDK credential
refresh performs a nested STS call. The request's original output, metadata and
error pass through unchanged; observation does not alter retries or authentication.

Recording performs no diagnostic I/O and retains no input, response, error,
URL/header, request ID or credential objects. A mutex-protected collector holds at
most 64 pending summaries. Overflow drops further summaries and prints an omission
notice when drained. The CLI drains after lifecycle stages; refresh calls during
a remote operation are reported when it ends, not synchronously with terminal
traffic. Cleanup runs before its report and drains its metrics afterwards. Late
concurrent observations may miss the last drain; debug output is not an audit log.
SDK clients capture the collector, so a fresh cleanup context can still record
termination without inheriting the canceled setup/session deadline.

Stages never contain raw error text, SDK objects, credential fields, request
headers, signed URLs, session tokens, MFA input, command/reason text or remote
payloads. Remote command stdout/stderr remain intentional separate output;
local diagnostics never enter stdout. Command failures retain verified exit
status only when no local diagnostic/cleanup error exists.

Verbose/debug writes use private terminal Streams without changing inherited
descriptor flags. Pipe/TTY writes use a one-second budget and also use the
remaining setup deadline before establishment. After establishment/when
reporting cleanup, the one-second diagnostic budget is independent of session
cancellation. Failed writers are not retried. Regular files retain Stream's
possible non-interruptible kernel-I/O limitation. Cleanup is attempted before
its diagnostic report; failure to report cannot skip that AWS attempt. Reporting
and descriptor-close errors remain visible failures, not fabricated remote status.

Tests exercise actual SDK serialization, signing, retry behavior, summaries and
CLI ownership with synthetic HTTP responses. They verify successful StartSession
responses remain usable even if subsequent stderr reporting fails. No live AWS
interoperability or release security certification is implied.
