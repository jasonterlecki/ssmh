# ssmh

`ssmh` is being implemented as a Linux Go client for AWS Systems Manager Session
Manager. The requested application uses IAM authentication and SSM sessions,
without SSH keys, port 22, a public IP, or an SSH daemon.

**Current status: initial native shell/command/forwarding client; development only.**
Shell sessions by EC2 instance ID or exact Name are wired end to end through SDK authentication,
SSM, the native channel, terminal handling, and owned-session cleanup. The owner
has verified a basic live shell using the default profile in us-east-1, including
clean remote `exit` after the cleanup fix. Broader live interoperability remains
unverified; this is not production-ready. See the acceptance audit for scope.
The [requirement-by-requirement acceptance audit](docs/acceptance.md) separates
implemented/local-tested behavior from the missing live evidence and plugin work.
Remote commands are wired through noninteractive sessions with document preflight,
separate output and verified exit status; compatible documents are required.
Native TCP forwarding is wired through fixed AWS documents, exact-destination
Port negotiation and bounded multiplexed socket serving on `127.0.0.1`.
Read-only `--list` and `--check`/JSON are implemented. Plugin compatibility remains
incomplete and returns an explicit error before AWS calls. Every session resolves
one exact EC2 ID or Name, requires running, then checks Linux/Online SSM registration.
Duplicate exact Names require an explicit ID, including stopped/offline duplicates.
That check validates every returned page and accepts only one exact EC2
registration with known metadata. Duplicate/unexpected targets, malformed status
or pagination failure stop setup before StartSession; no partial result is used.
The read-only EC2 discovery/exact-Name resolver and SSM inventory libraries are
implemented and used by listing/checks and all session modes. Session setup now
requires read-only `ec2:DescribeInstances` even when an explicit ID is supplied.
See [discovery status and safety limits](docs/discovery.md).

```sh
./bin/ssmh -i web-prod --region ca-central-1 --profile production
./bin/ssmh --list --region ca-central-1 --profile production
./bin/ssmh --list --json --name 'web-prod' --tag Environment=Production \
  --region ca-central-1 --profile production
```

Listing defaults to EC2 state running and includes only SSM Online registrations.
Use `--state` to choose another exact state; an empty successful JSON list is `[]`.
Names/tags are literal and case sensitive, not wildcard patterns. Listing shows
platform but does not prove Linux/native compatibility, current reachability or
StartSession authorization. It requires read-only `ec2:DescribeInstances` and
`ssm:DescribeInstanceInformation`, never a permission-test session. JSON goes only
to stdout; verbose/debug diagnostics go to stderr.

```sh
./bin/ssmh --check -i web-prod --region ca-central-1 --profile production
./bin/ssmh --check --json -i i-0123456789abcdef0 --region ca-central-1
```

Checks resolve an ID or one exact Name, require EC2 running and SSM Linux/Online,
and validate the default native shell document without starting a session.
STS metadata is reported when available; an explicit metadata-access denial is
shown as unavailable without switching credentials. Other identity/authentication
failures stop the check. A passing result means inspected prerequisites only:
StartSession authorization, live transport and later resource state are unverified.
JSON's `session_permissions_verified` remains false. `--check` needs no stdin and
checks the default shell, not command/forwarding/custom-document session options.
See [readiness semantics and limits](docs/discovery.md).

See the [security model and deployment review](docs/security.md) for implemented
trust boundaries, remote privilege and terminal-output risks, AWS logging
visibility, and best-effort cleanup. The client does not invoke `sudo`, but the
remote account can already have administrative privileges. Raw remote output is
not a terminal-safety filter, and local diagnostic silence does not imply that
AWS or the target records no session data.

## Build and initial usage

```sh
make build
./bin/ssmh --help
./bin/ssmh --version
./bin/ssmh -i i-0123456789abcdef0 -p production -r ca-central-1
```

Plain `go build` at the repository root also produces `./ssmh` through the same
process/CLI implementation. Use `CGO_ENABLED=0 go build` for a CGO-free local
binary, or `make release` for the stripped, path-trimmed cross-builds below.

Go 1.27.2 or later is required to build, not to run the resulting executable.
`make release VERSION=v0.1.0-dev` builds CGO-free, path-trimmed, stripped Linux
AMD64 and ARM64 binaries in `dist/`; it does not publish them or imply a release
has passed all security gates. Override `GO` when needed (for example
`make GO=/snap/go/current/bin/go build`). No Git metadata is required.
`make verify-release` separately tests byte-identical AMD64/ARM64 release builds
from two source locations with the same toolchain and cached dependencies; see
[release verification](docs/development.md). It does not prove live AWS behavior.
Install a reviewed binary by copying it to a user-owned directory on PATH; no
installation script or privileged operation is required.

The target needs a functioning SSM Agent, an authorized instance profile, and
network access to the relevant AWS endpoints. The caller needs permission for
EC2 DescribeInstances, SSM DescribeInstanceInformation, GetDocument for shells/commands, StartSession (including the selected document),
and cleanup of its own session. Explicit roles also require STS AssumeRole and
appropriate trust policy. SDK credentials/IAM Identity Center login must already
be available. AWS authorization remains authoritative; Online status does not
prove StartSession permission. The default session document and remote user are
controlled by Session Manager; the client does not request root or modify IAM,
instance settings, or security groups.
On normal authenticated remote shell closure, successful local shutdown releases
ownership without a redundant TerminateSession call, following the official
plugin's shell behavior. Local disconnects, cancellation and failures still
attempt explicit best-effort termination. Commands and forwarding keep explicit
cleanup; a ValidationException is not silently treated as success.
See [IAM permissions and deployment prerequisites](docs/iam-policy.md) for a
single-instance policy review template, IAM-user versus federated cleanup,
necessary wildcard read access, and an unresolved AWS data-channel scoping
documentation conflict. The example is not live-validated and grants no IAM,
agent-update or security-group administration.

```sh
./bin/ssmh -i i-0123456789abcdef0 --region ca-central-1 \
  --profile management --arn arn:aws:iam::123456789012:role/RemoteAccess \
  --session-name ssmh-session --reason "Incident investigation"
```

`--timeout` (default 30s) bounds authentication through channel handshake.
For forwarding it also covers listener creation; a port conflict stops before AWS
authentication and never causes another port or elevated bind to be attempted.
`--duration` optionally limits the local owned-session lifetime, starting after
StartSession succeeds; otherwise there is no client duration limit. `--document`
is passed unchanged; omitting it for shells preserves the account default. Shell
preflight reads `SSM-SessionManagerRunShell` (or the explicit document) and requires
an active JSON schema 1.0 Standard_Stream document with known preferences and a
literal supported KMS key or no key. KMS shells use the selected SDK identity
for GenerateDataKey and verify an encrypted challenge before readiness.
Missing/unreadable documents fail closed; the client does not create
preferences or substitute a document. Native readiness requires a matching
handshake or the verified non-KMS shell's first ordered output. `auto` currently selects
native only; no SSH, plugin, or AWS CLI fallback occurs. Normal diagnostics use
stderr; `--quiet` suppresses information, never errors. `--verbose`/`--debug`
add allowlisted lifecycle stages and a validated STS account/principal lookup
using the already selected credentials and setup deadline. Identity failure stops
setup; identity success does not prove SSM permission. Default/quiet session and
list invocations make no extra STS identity request. Read-only `--check` always
queries identity, allowing only explicit metadata-access denial to be reported
as unavailable without changing credentials. Debug reports stage durations and allowlisted
EC2/STS/SSM SDK operation durations with retry-loop attempt/retry counts. No SDK
request/header dumps, credentials, commands, reason
text or terminal payloads enter these diagnostics. Pipe/TTY diagnostic writes
have a one-second write budget, additionally bounded by setup before establishment.
Cleanup is attempted before its diagnostic output; regular-file I/O retains the
kernel-blocking limitation documented below. API summaries are buffered without
I/O inside SDK calls, then drained at lifecycle boundaries; at most 64 pending
summaries are retained and overflow is reported. Attempt counts are SDK retry-loop
counts, not exact HTTP transmission counts. Verbose/debug also report fixed
credential-source labels from SDK numeric metadata, without retrieving credentials
again or inspecting their contents. Unknown metadata is reported as unavailable;
labels are not a credential-search/refresh history or proof of authorization.
Debug additionally reports fixed native WebSocket/readiness/publication/retry/end
states from a bounded 64-event collector, drained at stage boundaries without
transport-loop I/O. It never prints frames, payloads, identifiers or authentication
fields; socket closure does not prove AWS session cleanup. Other API pairs and
more detailed protocol diagnostics remain unfinished. Verbose/debug report a
fixed local termination reason after the owned AWS cleanup attempt. A successful
operation return can mean remote completion or a local disconnect; the client
does not invent a remote cause or hide independent cleanup failures.
See [diagnostic behavior and limits](docs/diagnostics.md).
For stage-specific failures and safe corrective checks, see
[troubleshooting](docs/troubleshooting.md); do not disable validation to diagnose
TLS, protocol or authorization failures.
Local exit codes are 0 for normal completion/local escape, 2 for invalid or
unfinished operations, 130 for cancellation, and 1 for other failures. These
codes are not fabricated remote shell exit status.

For commands, `-c` is interpreted by remote `/bin/sh -c`, never a local shell.
`ssmh` checks the selected document with `ssm:GetDocument` before StartSession
and requires NonInteractiveCommands, separate output and no elevation. The
default command document is AWS-StartNonInteractiveCommand; if it is incompatible,
select a reviewed custom document rather than weakening validation. See
[remote commands](docs/remote-commands.md) for a document example, quoting,
permissions, exit-code behavior and limitations.

```sh
./bin/ssmh -i i-0123456789abcdef0 -r ca-central-1 \
  --document SafeCommand -c 'printf "%s\\n" "hello"; exit 42'
```

Command status is propagated only after validated output/status/owned close and
successful AWS cleanup. Local failures remain local errors; cleanup failures do
not disappear behind a remote exit code. No stdin or raw terminal is used.

Implemented library components include:

- GNU-style option parsing and validation, including role ARNs and forwarding
  destinations. Forwarding addresses are restricted to `127.0.0.1`; a validated
  address is not an implemented tunnel.
- Standard AWS SDK for Go v2 credential loading, explicit profile selection,
  region precedence, and explicit STS AssumeRole using a refreshable credential
  cache. Role failures fail closed. MFA refresh requires a fresh code.
- SSM session creation, authenticated endpoint validation, process-owned cleanup,
  and paginated SSM readiness checks. Readiness does not start a test session and
  does not prove permission to start sessions.
- Allowlisted AWS errors and sanitization of diagnostic metadata. SDK errors can
  contain sensitive information and are never passed directly to diagnostics.
- A native SSM data channel with TLS/SigV4 authentication, AWS framing,
  handshake, ordered output, acknowledgement validation, bounded buffers and
  retransmissions, resize messages, and cancellation. In-memory tests exercise
  bidirectional streaming and real TLS certificate/HTTP upgrade validation.
  It is integrated into the native-shell CLI; a basic owner-run live shell works,
  but broader protocol/TTY interoperability remains unverified.
- Linux terminal primitives: raw mode with full-state restoration, dimensions,
  streaming line-start escapes, and cancellable pipe/TTY I/O without modifying
  inherited descriptor flags. The shell-loop library now wires input/output,
  initial/resized dimensions, TTY-only `~.` disconnect/`~~` literal escapes, and
  external termination signals to an established native channel. Ctrl+C/Ctrl+D
  are sent remotely in raw mode; piped input EOF sends one Ctrl+D and drains
  remaining output. Workers stop before terminal restoration. Private pipe/TTY
  descriptors require mounted procfs;
  regular-file I/O may block in the kernel despite context cancellation.
- Noninteractive command execution with bounded remote shell serialization,
  authenticated document preflight, separate output, verified typed status,
  no stdin/raw mode and owned-session cleanup. Live AWS interoperability remains
  unverified. See [command requirements](docs/remote-commands.md).

Optional live native tests now exist for read-only checks, piped shells, command
streams/exit status and forwarding to an approved existing echo service. They
skip by default, require explicit operation/target/account selection, provision
no resources, and have not yet been run against AWS. See
[live test authorization and invocation](docs/development.md).

Native forwarding now composes listener creation, selected SDK authentication,
Linux/Online SSM verification, fixed-document owned StartSession, strict Port
negotiation and bounded smux/socket serving. It requires agent version strictly
greater than 3.1.1511.0 and refuses required KMS, unsupported properties or a
different destination. See [forwarding behavior and validation limits](docs/native-forwarding.md).

```sh
./bin/ssmh -i i-0123456789abcdef0 -r ca-central-1 -L 8080:80
./bin/ssmh -i i-0123456789abcdef0 -r ca-central-1 \
  --forward-host 15432:database.internal:5432
```

Only TCP4 `127.0.0.1` listeners are supported. IPv6 remote host literals use
brackets in the argument, e.g. `8080:[2001:db8::1]:80`; remote DNS is resolved by
the agent, not locally. Informational stderr reports the listening address and
destination after validated channel readiness; quiet suppresses it. Stop with
Ctrl+C. Forwarding never reads stdin or enters terminal raw mode. Local resources
close before fresh ten-second best-effort AWS termination. No independent TCP
half-close is promised; unscoped destination errors stop the whole tunnel.
Loopback does not authenticate local users: do not expose sensitive services on
an untrusted shared host. The opt-in OS loopback listener test now passes after
user-enabled network access; live AWS
interoperability remains unverified; this is development functionality.
Native control JSON rejects duplicate fields and case aliases before accepting
handshake, acknowledgement or owned-close decisions. Native sockets/handshakes
advertise fixed numeric wire compatibility `1.2.339.0`, not ssmh's release version,
for verified output-separation/mux feature thresholds; unsupported features still
fail closed. Structural limits are
documented in [the protocol guide](docs/native-protocol.md).
Native KMS shell/command encryption has synthetic TLS/SDK coverage, not live AWS proof.
The transport refuses unverified KMS actions and KMS forwarding sessions,
unverified handshake-free sessions, and unrecognized session types.
It fails closed instead of silently changing the requested operation or reducing
encryption. The official plugin compatibility backend is still incomplete.
Executable discovery/version probing and an in-memory owned-session response
handoff primitive are implemented as libraries. They do not enable
`--backend plugin` or launch official plugin sessions. A selected-SDK-provider
credential-response adapter also preserves expiration in its wire encoding;
its private authenticated loopback relay is implemented and tested with synthetic
credentials. An explicit child credential-environment builder is also tested;
plugin process/network-policy integration remains pending. A read-only Linux
logging prerequisite now refuses unprotected installations and anything except
the narrow disabled configuration; it is not yet integrated into a launcher.
The reviewed Linux
plugin additionally uses a trusted `stty` terminal helper. Native sessions need
neither that helper nor a credential relay. See
[plugin preflight and remaining launch work](docs/plugin-backend.md), and
[docs/native-protocol.md](docs/native-protocol.md) for references and limits.
The plugin guide records upstream logging, mixed-output and independent
credential-loading constraints; environment isolation alone does not solve them.
Current Standard_Stream agents omit the handshake without KMS; that authenticated
path is supported only after shell document preflight. A shell that emits no
initial output can still hit the establishment timeout. Authorized document
administrators remain trusted: StartSession cannot pin a document version and a
concurrent default-version change cannot be ruled out. KMS shells negotiate the
exact document-selected key, owned session/target/random context and encrypted
challenge, never handshake-free output. The caller needs kms:GenerateDataKey and
the target needs kms:Decrypt on the selected key under applicable IAM/key policies.
Non-secret context fields can appear in CloudTrail. Key/alias admins remain
trusted; parameterized key expressions are unsupported. Compatible command
documents can select the same literal KMS inputs. Commands always require the
handshake; encrypted stdout, stderr and typed exit status use that owned command
capability, never a shell capability. No document/permission changes are automatic.

Development requires Go 1.27.2 or later. The local module name is `ssmh`; no Git
URL is asserted by that module path; no license has been selected. No Git initialization is required.
See [development and verification](docs/development.md) for actual Makefile
targets, offline/opt-in test limits and release gates, and
[architecture](docs/architecture.md) for current component/resource ownership.

```sh
go mod verify
go vet ./...
go test ./...
go test -race ./...
```

On this development host, the Snap launcher fails but its native binaries work:

```sh
GOCACHE=/tmp/ssmh-go-build /snap/go/current/bin/go test ./...
```

The dependency versions are pinned to SDK modules available in the development
cache. After upgrading the module minimum to patched Go 1.27.2, govulncheck
reports no vulnerabilities (2026-10-09). Repeat scans and dependency review before
releases; this is not a security certification or live interoperability proof.
Tests use synthetic credentials and mocked AWS service calls; they do not
contact AWS, create resources, or require live credentials.

See the [authentication guide](docs/authentication.md) for profile selection,
SSO setup, explicit roles, secure MFA and expiration/cleanup limits. SDK SSO
refresh may rewrite its existing token cache; protect that cache and its existing
permissions. No application-owned credential storage is introduced.
New SDK login-cache files use owner-only permissions; inherited unrestricted
settings do not weaken that policy. Existing login/SSO file modes are preserved,
so protect those separately. See the authentication guide for scope and limits.

The implemented authentication interface respects environment credentials, AWS
shared files, credential processes, role profiles, ECS/EC2 credentials, and IAM
Identity Center through the SDK. IAM Identity Center login must already be
available in the standard SDK cache. The application will not require AWS CLI
for sessions. When explicit role MFA or an SDK role profile requires a code,
the CLI prompts on `/dev/tty` with echo disabled and full terminal restoration.
It never reads redirected stdin for MFA; unattended invocations must supply
usable preauthenticated SDK credentials. Enter only the requested six digits:
queued/typeahead input is cleared before and after the prompt to keep pasted
codes out of a subsequent remote shell. Ctrl+C cancels setup. The setup deadline
also bounds prompting; use `--timeout` if authentication needs more time.

An explicit one-use `--mfa-token` with `--mfa-serial` is also accepted, but process
arguments can expose it to local process inspection; interactive prompting is
preferred. Each setup refresh obtains a fresh code. Once the channel is
established, prompting is permanently disabled to protect remote terminal input.
Later refresh requiring MFA fails closed, including owned-session cleanup if
credentials have expired. This can leave a session needing manual cleanup;
the failure is reported and cleanup is never claimed guaranteed. The SDK still
refreshes providers that need no interactive MFA. Codes are not persisted or
logged, but erasure of Go/SDK string memory cannot be guaranteed.

Custom AWS service endpoints are deliberately unsupported. Signed AWS requests
require HTTPS and recognized AWS endpoint suffixes; redirects are disabled.
Current session stream validation accepts exact regional `ssmmessages` hosts in
commercial, China, and GovCloud regions. Other partitions and alternate stream
endpoints are not supported yet. TLS verification remains enabled and normal
HTTP proxy configuration is preserved.
Optional `--ca-cert path/ca-bundle.pem` (alias `-ca`) selects a PEM CA bundle for
SDK requests and the native WebSocket. It overrides `AWS_CA_BUNDLE` and the
selected profile's `ca_bundle`; without it, existing SDK precedence is unchanged.
The CLI accepts a regular file up to 4 MiB, including relative paths.
Invalid bundles fail closed; explicit roots replace system defaults,
so include all required AWS/proxy trust roots. Certificate/hostname verification,
redirect refusal and signed-endpoint guards remain enabled. See
[custom CA behavior](docs/authentication.md).

```sh
./dist/ssmh-linux-amd64 -i i-0123456789abcdef0 -r us-east-1 -p default \
  -ca path/ca-bundle.pem
```

Cleanup is best effort, retryable after failure, and restricted to sessions
returned by this process's successful StartSession call. No client can guarantee
cleanup after SIGKILL, power loss, or loss of AWS connectivity. A malformed AWS
response without a valid session ID cannot be cleaned up safely and is reported.

See [PROMPT.md](PROMPT.md) for the full requested features and
[CODEX.md](CODEX.md) for the current implementation map and planned architecture.
