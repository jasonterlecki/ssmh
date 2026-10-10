
# CODEX.md
# ssmh - Repository Structure and Architecture Reference

## 1. Purpose

This document is the authoritative repository map and architectural
reference for `ssmh`.

`ssmh` is a native Linux command-line application written in Go that
provides SSH-like remote access to Amazon EC2 instances using AWS
Systems Manager (SSM) Session Manager instead of SSH.

This document describes:

- The proposed repository structure.
- The purpose of each directory and file.
- Package responsibilities and dependencies.
- Security boundaries.
- Major application workflows.
- Architectural decisions.
- Testing and build organization.
- Implemented, planned, and deprecated components.

All coding agents MUST read `AGENTS.md` and this document before
making changes.

All coding agents MUST automatically update this document when repository
structure, component responsibilities, interfaces, architectural relationships,
security boundaries, or implementation status changes. Maintaining this map is
an inseparable part of every development task and requires no separate user
request. See `AGENTS.md` for the mandatory synchronization and completion-gate
requirements.

Security rules are defined in `AGENTS.md`. If there is a conflict,
the applicable security requirements take precedence.

---

## 2. Repository Status

**Status: Initial native shell/command/forwarding executable; full requested feature set in progress**

The repository now has a local Go module (`ssmh`, derived from the directory
name; no remote URL is asserted). Implemented source files are
`internal/config/config.go` (invocation, region, role, and forwarding validation),
`internal/cli/flags.go` (argument parsing), `internal/aws/client.go` (SDK credential
chain and refreshable explicit AssumeRole), `internal/ssm/session.go` (owned session
creation, validated transport material and retryable cleanup),
`internal/ssm/availability.go` (complete bounded exact-target readiness), and
`internal/logging/errors.go` (allowlisted error messages and metadata sanitization).
Each has a colocated `_test.go` file covering its implemented behavior with
synthetic credentials and service mocks. `go.sum` is generated; the existing
packages pass unit tests, race tests, `go vet`, and module verification. The
libraries compile with CGO disabled for Linux AMD64 and ARM64. `README.md`
documents the initial executable and limitations. Root `main.go` and
`cmd/ssmh/main.go` share `internal/app/execute.go` for top-level signal
cancellation, final stderr reporting and exit status; plain root `go build` is
supported without duplicating session/process ownership. `internal/cli/root.go` routes
help/version, read-only list/check/JSON and native sessions by instance ID or exact Name; unfinished CLI modes
are refused before authentication. `connect.go` composes SDK loading, complete exact
EC2 resolution/running-state validation, Linux SSM
Online verification, owned StartSession, native Connect and terminal Run.
Authenticated document preflight precedes shell/command session creation. One
setup budget bounds all establishment stages; optional duration bounds the owned
session lifetime. Cleanup uses a fresh ten-second context after terminal shutdown.
`internal/version/version.go` supplies linker-injected version metadata.
`aws/identity.go` adds read-only STS caller metadata through `IdentityAPI`, with
bounded account/ARN validation and no credential/UserId fields or fallback.
`cli/diagnostics.go` supplies allowlisted lifecycle stages and debug stage
durations; session/list identity lookup is opt-in through verbose/debug and shares
the setup deadline. Check always queries identity through its read-only workflow.
Identity success does not prove SSM authorization. Default/quiet session/list
invocations make no added STS identity request. Diagnostic failures are reported
without preventing cleanup of a session already created. Private terminal
Streams bound pipe/TTY writes to one second (and the setup deadline before
establishment); failed diagnostic writers are not retried. Cleanup precedes its
report, and diagnostic descriptors close after owned cleanup. Regular-file I/O
retains Stream's kernel-blocking limitation. `aws/metrics.go` now adds debug-only
SDK operation durations and retry-loop counts for allowlisted EC2/STS/SSM/KMS calls through
APIOptions Initialize middleware. It passes inputs/results/errors unchanged and
records no raw objects or secret-bearing fields. A mutex-protected collector caps
pending summaries at 64 and reports omissions; StartSession summaries drain only
after ownership tracking, and cleanup precedes its metric output. SDK clients
capture the collector independently of request contexts, including fresh cleanup
contexts. Counts describe SDK retry-loop entries, not HTTP transmissions; absent
metadata is unavailable. `aws/credentials.go` adds bounded verbose/debug source
classification using SDK `CredentialProviderSource` numeric metadata, never
credential retrieval or arbitrary provider strings. Unknown/missing/oversized
metadata prints unavailable without changing authentication. Labels describe
reported sources, not search history; explicit AssumeRole reports its final
provider rather than reconstructing the base chain. Native debug observation in
`native/trace.go` records fixed WebSocket/readiness/publication/retransmission/end
states, capped at 64 pending events with explicit omissions, no raw data or I/O
in the transport loop. CLI drains at lifecycle boundaries through private writers;
the context preserves lifetime cancellation without inheriting setup's deadline.
The production native adapter returns a true nil Channel interface on setup
failure, preventing typed-nil Close panics; CLI regression coverage uses the real
adapter and verifies fresh owned-session termination after native refusal.
EC2 DescribeInstances now has debug-only per-call summaries, including SDK retries;
exact filters, Names/IDs, pagination/request IDs and response/error values remain
excluded. Actual signed SDK XML/retry fixtures test debug gating, unchanged
responses/failures and fixed labels; CLI synthetic SDK tests require its summary.
KMS GenerateDataKey also records fixed debug-only timing/retry summaries through
the selected config's captured collector, without key references, encryption
context or key material. Signed synthetic SDK tests verify debug gating, retries,
unchanged responses/errors and omission of unrelated KMS operations.
Other API pairs and more detailed protocol diagnostics remain unfinished.
`aws/metrics_test.go` exercises actual signed SDK calls/retries,
success/error transparency, unknown-label omission and bounded concurrent drains;
`cli/api_diagnostics_test.go` composes real SDK loading/services with synthetic HTTP,
tests mode separation and verifies post-Start report failure still terminates ownership.
`aws/identity_test.go` covers safe metadata, malformed/ambiguous responses,
partitions, cancellation, redacted API failures, actual SDK STS serialization/
response decoding with a synthetic HTTP client, and fuzz parsing.
`aws/credentials_test.go` checks every numeric source label, bounded/unknown
metadata, no extra retrieval, actual SDK environment/profile resolution and the
final explicit AssumeRole provider. `cli/diagnostics_test.go` checks opt-in
metadata inspection/reporting, opt-in STS calls, setup budget, all fixed stages,
stream separation, raw-error omission, bounded/full/broken pipes, owned cleanup
and remote exit status versus local reporting failure. `docs/diagnostics.md`
documents implemented stage/API/provider reporting and remaining protocol gaps.
`docs/authentication.md` explains SDK selection, modern SSO configuration and
login prerequisites, explicit roles/MFA, cache writes, and authentication limits.
`tests/documentation/authentication_test.go` parses its SSO config through the
actual SDK and its client commands through the CLI, without executing or authenticating.
`docs/iam-policy.md` maps implemented caller API permissions and prerequisites,
provides narrow IAM-user shell and source AssumeRole examples, and distinguishes
federated cleanup, agent roles and future-feature permissions. It explicitly
records conflicting AWS OpenDataChannel scoping guidance and unverified live IAM
effectiveness. `tests/documentation/iam_policy_test.go` checks embedded policy JSON
and intended action/resource/condition scope offline, not AWS authorization.
`Makefile` builds local and CGO-free Linux AMD64/ARM64 executables, and exposes
test/race/vet/module/vulnerability validation targets. Build recipes do not need
Git metadata. `verify-release` opts into `tests/build/release_test.go`, which runs
the actual release recipe twice from isolated source-only roots with cached
dependencies, compares both architecture artifacts byte-for-byte, checks static
ELF/build metadata and probes the host-architecture version. It also runs plain
root `go build`, verifies its default version and compares both entry points'
compiled help. Ordinary tests only
check its gate/environment isolation; reproducibility results require an actual
opt-in run. Plugin backend remains incomplete. Forwarding is
wired into the development CLI; the opt-in OS loopback listener test passes,
while live AWS validation remains pending.
`ssm/status.go` implements the read-only SSM inventory half of
discovery through `StatusAPI`: EC2 registration filter, 50-row pages, bounded
tokens/pages/10000 records, duplicate-ID rejection, validated availability DTOs,
and sorted all-or-error results. `internal/ec2/discovery.go` now provides SDK v2
read-only DescribeInstances pagination, exact literal Name/state/tag filters,
validated ID/state/optional IPv4/Name DTOs and sorted all-or-error results.
`resolver.go` resolves an ID or exact Name only after complete pagination and
rejects absent/ambiguous targets, including stopped-name duplicates. The pinned
EC2 SDK v1.304.0 requires no upgrade of the existing dependency set. There are
no EC2 writes or session permission probes. `docs/discovery.md` records verified AWS
references and limits. `cli/list.go` now joins complete EC2/SSM inventories by exact
ID through separate read-only clients sharing the selected SDK config; it defaults
to running and includes only SSM Online registrations. It never constructs a
session-control client, opens a channel, binds a port, reads stdin or alters a TTY.
`cli/output.go` formats all seven columns with sanitized Names or ASCII-only JSON
that preserves exact Unicode after decoding. No partial inventory is emitted;
failed output can leave incomplete bytes and returns failure. Query.Validate
rejects bad/duplicate/excessive filters before authentication. One timeout covers
auth, APIs and output; stdout uses a private Stream with at most ten seconds for
writing. Verbose/debug identity and bounded stderr remain opt-in; selected-provider
MFA prompts are disabled before output. HTTP pools/descriptors close on all
controllable exits. `list_test.go` covers pagination/join/filter/status semantics,
option fidelity, deadline/failure/no-partial-result behavior, stream separation,
Unicode formatting, broken writers and actual signed SDK HTTP/XML/JSON fixtures.
The executable child tests in cmd/ssmh/main_test.go now use invalid-list predicates
instead of treating list as unsupported, and isolate AWS environment/shared-file
providers with IMDS disabled. This prevents host credentials/configuration from
being selected if help/error routing regresses. `cli/check.go` now reads STS identity,
resolves an exact EC2 ID/Name after all pages, requires running and Linux/SSM Online,
and uses a read-only default shell-document preflight. It never constructs the
session-control client, connects a channel or binds a listener. Only explicit STS
metadata AccessDenied is classified as unavailable and allowed to continue using
the exact same selected config; expired/invalid credentials, TLS/network errors,
malformed identity and cancellation still fail. aws.ErrIdentityDenied retains no
raw cause; ordinary session/list identity diagnostics still fail on denial.
Human/ASCII JSON reports say prerequisites only and session_permissions_verified
is false; no StartSession permission/data-channel proof is asserted. Shared output
encoding preserves decoded Unicode and bounded private writers/MFA/HTTP cleanup
follow listing's ownership rules. Check/JSON needs no stdin; native is the compiled
backend and plugin stays unsupported. All connection modes now resolve one exact
EC2 ID/Name after all pages and require running before SSM/session creation; SSM Online
never proves StartSession authorization or native/Linux compatibility.
`cli/mfa.go` serializes SDK callbacks against the setup deadline and
permanently disables prompts before terminal Run, including later cleanup.
Cleanup also disables prompting after early channel-establishment failures so
callbacks cannot extend the independent cleanup budget or steal terminal input.
`terminal/mfa_linux.go` supplies bounded no-echo controlling-terminal prompting,
complete restoration and clearing of queued/typeahead input. Redirected stdin is
never used for MFA. Live AWS interoperability is not verified.

`internal/command/execute.go` now provides a no-input command-result
receiver for an already authenticated NonInteractiveCommands channel. It drains
separate stdout/stderr through private cancellable terminal Streams and closes
the channel before returning. `exitcode.go` validates AWS's typed ASCII exit-code
payload. A Result is known only after one valid 0–255 status, owned-session EOF,
output delivery and successful cleanup; all errors invalidate it. The CLI now
enables `--command` through CLI lifecycle integration: compatible documents are
checked before StartSession, NonInteractiveCommands is negotiated, and command
results map to process status only after owned cleanup. No command text is
executed locally. Managed/default command documents that lack separate output
or request elevation are refused; an explicitly selected compatible document
is needed in those accounts. CLI compatibility/live AWS validation remain pending.
`command/quote.go` serializes a bounded UTF-8 command as one remote `/bin/sh -c`
argument using POSIX quoting; nothing is executed locally. `ssm/documents.go`
adds a read-only GetDocument preflight: active JSON Session document, exact
NonInteractiveCommands type, unchanged String command placeholder, explicit
non-elevated Linux execution, separate output and empty prefixes. Parsing rejects
unknown fields, duplicate keys, excessive nesting and oversized content. Linux
command-policy fields require exact JSON names at root/parameter/property
boundaries; case variants and null/non-string separators fail closed. Read-only
preflight rejects missing context/client and cancellation before/after the API,
with regression coverage for these boundaries. It
reads the default version; authorized document administrators remain trusted
because StartSession cannot pin the version against concurrent document changes.
`execute_test.go` and `exitcode_test.go` cover separate raw output, status
impersonation, all allowed statuses, malformed/duplicate/unavailable status,
post-status output, disconnect, output cancellation and channel-close failures;
the parser also has a fuzz target. `docs/remote-commands.md` documents the
verified agent behavior, receiver contract, document/quoting boundary and limits.
`quote_test.go` covers quoting round trips and fuzzing; `ssm/documents_test.go`
covers safe/unsafe properties, exact policy names, cancellation before/after reads,
document identity/status, redacted SDK failures and bounded parser fuzzing.
`cli/command_test.go` verifies case-variant/null-prefix documents fail before
StartSession, and covers parameter/document
preservation, no terminal input, separate output, status propagation and owned
cleanup failure overriding remote status.
Native protocol tests also verify typed status is delivered only after negotiated
NonInteractiveCommands handshake and wire retransmissions are suppressed.
Owned-close processing now rejects pending reorder-buffer sequence gaps rather
than presenting incomplete output as normal EOF; protocol regression tests cover
this boundary. `ssm/shell.go` adds `StartShell`: authenticated default-version
document preflight verifies schema 1.0 Standard_Stream and literal absent/empty
KMS selection before starting a session. Only that owned session can authorize
native readiness on its first ordered Output frame without a handshake, matching
the official agent's non-KMS shell behavior. Unreadable/missing preferences,
unknown fields, parameterized/invalid KMS and wrong session types fail closed.
The default read is SSM-SessionManagerRunShell; StartSession still leaves
DocumentName unset, preserving account defaults. Document administrators remain
trusted because StartSession cannot pin the preflight version. Later/required
KMS shells retain the document-selected literal key, require the encrypted
handshake and use selected-config key preparation; commands always require their
handshake and cannot use the shell KMS capability. `StartCommand` verifies its own
document/literal inputs, binds the KMS key to NonInteractiveCommands and keeps
selected identity/region. Connect uses that type-bound capability for encrypted
stdout/stderr/typed status; nil/unowned/terminated sessions grant no key. Live KMS
remains unverified.
`ssm/shell_test.go` covers preflight selection, malformed/encrypted documents,
cleanup and capability lifetime; its parser has a fuzz target. `cli/shell_test.go`
covers preflight-before-Start and capability forwarding. Native protocol tests
cover strict defaults, ordering, duplicates, corrupt/late negotiation, KMS refusal
and command isolation. `native/shell_test.go` exercises real TLS/SigV4/token
exchange and native Connect through the StartShell ownership boundary without
live AWS or OS sockets; it verifies retained first output and resize sequence 0.

`internal/terminal/terminal_linux.go` now implements Linux raw-mode activation,
complete saved-state restoration (retryable after failure), TTY detection, and
dimension queries through `golang.org/x/sys/unix`. `escape.go` implements bounded
streaming line-start `~.` disconnect and `~~` literal handling; callers must use
it only for TTY input. `io_linux.go` owns private cancellable pipe/TTY descriptors
reopened through procfs, without changing inherited descriptor flags. Regular
files share the caller's offset and may incur non-interruptible filesystem I/O.
Colocated tests cover restoration, chunk boundaries, binary bytes, pipe
cancellation, descriptor ownership, and controlled Linux pseudo-terminals.
`session_linux.go` now connects these primitives to an established native shell
through the `Channel` boundary. It handles initial/changed dimensions, TTY-only
escapes, redirected input EOF, stdout/stderr routing, external termination
signals, bounded input chunks, and joined I/O cleanup before full restoration.
AWS session termination is owned by `cli/connect.go`, after terminal Run returns.
`session_linux_test.go` exercises the shell loop with synthetic channels and real
PTYs, including resized dimensions, physical control bytes, restoration after
local escape/cancellation, redirected binary input, output draining, chunk bounds,
and joined cleanup failures. A subprocess test verifies actual external SIGTERM
delivery reaches controlled channel cleanup. Descriptor access uses SyscallConn,
not File.Fd (which can itself change Go-managed nonblocking flags); the regression
test captures inherited flags before any such conversion.

Native transport is now in progress: `internal/transport/native/message.go`
implements the bounded AWS binary codec, canonical UUID formatting and wire
ordering, and redacted message formatting. `protocol.go` implements the
single-owner handshake/sequence/acknowledgement state machine. Each has a
colocated test file with synthetic fixtures and fuzz targets. `docs/native-protocol.md` records
official AWS references and validation boundaries. Native shell terminal/CLI
integration is implemented. Codec/protocol/TLS and synthetic streaming unit tests pass;
no live AWS session has been tested.

`stream.go` and `stream_test.go` add the native channel event loop and bounded
ordered output queue. The loop owns protocol state, joins its reader on exit,
applies producer backpressure, handles retransmissions and keepalive pings,
and distinguishes owned-session completion from disconnect/cancellation.
`Connect` applies one establishment budget through handshake/verified shell readiness; its
context controls the subsequent session lifetime. `Send` cancellation closes
the channel rather than permitting unsafe retries with unknown delivery.
SSM session cleanup and terminal management remain caller responsibilities.

`websocket.go` and its colocated tests now implement/test TLS HTTP upgrades,
SigV4/presigned authentication, OpenDataChannel token submission, client masking,
fragment reassembly, control frames, size bounds, cancellation, and redacted
connection failures. TLS roots/proxies are inherited from the configured AWS
HTTP client. No WebSocket extensions or compression are negotiated. Socket
integration with the channel loop is implemented; live AWS connectivity is not verified.
TLS tests use an in-memory listener and real TLS/HTTP processing without needing
OS socket access. Writes time out after ten seconds, pings run
each minute, and three minutes without a received frame ends the socket.

Security boundaries implemented so far: validation precedes API calls; role
failures return no usable configuration; tokens are held only in memory; session
ownership can only be obtained from successful StartSession; malformed session
responses cause best-effort cleanup; only exact regional commercial/China/GovCloud
SSM WebSocket endpoints are accepted. Other partitions and alternate endpoints
remain unsupported. Raw SDK errors are not displayed, because they may carry
credentials, tokens, URLs, or credential-process output.

AWS HTTP requests retain certificate validation, environment proxy support,
bounded retries, and timeouts; redirects and configured service endpoint overrides
are refused. Configured transports explicitly use HTTP/1.1, which AWS APIs
support and which the SSM WebSocket Upgrade requires. An HTTP transport guard also refuses signed AWS requests to insecure
or unrecognized service hosts. SDK-managed credential-provider endpoints remain
under SDK validation. Session formatting redacts authentication material, and
successful cleanup releases the session object's references to its token and URL
(this is not a guarantee that Go string memory is erased).

The remainder of this document describes the proposed architecture except where
the implementation inventory above explicitly identifies an existing component.

The files and directories listed below are not necessarily present.

Until the corresponding files are created, they must be considered
PLANNED rather than IMPLEMENTED.

There is currently no requirement for an initialized Git repository.

Do not run `git init` unless explicitly instructed.

### Implementation Status Definitions

- PLANNED: Proposed but not yet implemented.
- IN PROGRESS: Currently being implemented.
- IMPLEMENTED: Exists and has working functionality.
- TESTED: Implemented with relevant passing tests.
- DEPRECATED: Retained temporarily but scheduled for removal.

Codex MUST update status descriptions as development progresses.

Never mark a component IMPLEMENTED or TESTED without verification.

---

## 3. Current and Proposed Repository Structure

```text
ssmh/
│
├── AGENTS.md
├── CODEX.md
├── PROMPT.md
├── README.md
├── LICENSE
├── Makefile
├── main.go
├── go.mod
├── go.sum
├── .gitignore
├── .golangci.yml
│
├── cmd/
│   └── ssmh/
│       └── main.go
│
├── internal/
│   │
│   ├── app/
│   │   └── execute.go
│   │
│   ├── cli/
│   │   ├── root.go
│   │   ├── connect.go
│   │   ├── diagnostics.go
│   │   ├── list.go
│   │   ├── check.go
│   │   ├── forward.go
│   │   ├── flags.go
│   │   ├── native_command_tls_test.go
│   │   ├── native_executable_tls_test.go
│   │   └── output.go
│   │
│   ├── config/
│   │   ├── config.go
│   │   ├── kms.go
│   │   └── validate.go
│   │
│   ├── aws/
│   │   ├── client.go
│   │   ├── credentials.go
│   │   ├── assume_role.go
│   │   ├── region.go
│   │   ├── metrics.go
│   │   └── identity.go
│   │
│   ├── ec2/
│   │   ├── discovery.go
│   │   ├── resolver.go
│   │   └── instance.go
│   │
│   ├── ssm/
│   │   ├── client.go
│   │   ├── session.go
│   │   ├── lifecycle.go
│   │   ├── documents.go
│   │   ├── shell.go
│   │   ├── forward.go
│   │   ├── availability.go
│   │   └── status.go
│   │
│   ├── transport/
│   │   ├── transport.go
│   │   ├── native/
│   │   │   ├── websocket.go
│   │   │   ├── handshake.go
│   │   │   ├── message.go
│   │   │   ├── mux.go
│   │   │   ├── mux_state.go
│   │   │   ├── protocol.go
│   │   │   ├── encryption.go
│   │   │   ├── kms_protocol.go
│   │   │   ├── kms.go
│   │   │   ├── kms_connect_test.go
│   │   │   ├── port.go
│   │   │   ├── forward.go
│   │   │   ├── control_json.go
│   │   │   ├── trace.go
│   │   │   ├── sequence.go
│   │   │   └── stream.go
│   │   │
│   │   └── plugin/
│   │       ├── plugin.go
│   │       ├── handoff.go
│   │       ├── credentials.go
│   │       ├── credential_server.go
│   │       ├── environment.go
│   │       ├── logging_linux.go
│   │       └── process.go
│   │
│   ├── terminal/
│   │   ├── terminal.go
│   │   ├── rawmode.go
│   │   ├── resize.go
│   │   ├── signals.go
│   │   └── escape.go
│   │
│   ├── command/
│   │   ├── execute.go
│   │   ├── quote.go
│   │   └── exitcode.go
│   │
│   ├── forward/
│   │   ├── forward.go
│   │   ├── listener.go
│   │   ├── target.go
│   │   └── validate.go
│   │
│   ├── logging/
│   │   ├── logger.go
│   │   └── redact.go
│   │
│   └── version/
│       └── version.go
│
├── tests/
│   ├── build/
│   │   └── release_test.go
│   ├── documentation/
│   │   ├── acceptance_test.go
│   │   ├── authentication_test.go
│   │   ├── iam_policy_test.go
│   │   └── links_test.go
│   ├── integration/
│   │   ├── native_test.go
│   │   ├── guard_test.go
│   │   ├── tty_linux_test.go
│   │   ├── session_test.go
│   │   ├── command_test.go
│   │   └── forward_test.go
│   │
│   └── fixtures/
│       └── README.md
│
├── docs/
│   ├── architecture.md
│   ├── acceptance.md
│   ├── diagnostics.md
│   ├── discovery.md
│   ├── security.md
│   ├── authentication.md
│   ├── iam-policy.md
│   ├── native-protocol.md
│   ├── native-forwarding.md
│   ├── plugin-backend.md
│   ├── troubleshooting.md
│   └── development.md
│
└── dist/
    └── (generated binaries; ignored by Git)
```

This is the target logical structure, not a requirement to create
every file immediately.

Codex SHOULD create files and packages only when implementing
functionality that requires them.

Avoid empty placeholder packages.

---

## 4. Root Files

### AGENTS.md

Status: IMPLEMENTED

Purpose:

Defines mandatory engineering and security instructions for
AI coding agents.

Contains:

- Security requirements.
- Credential-handling rules.
- Coding standards.
- Testing requirements.
- Documentation maintenance rules.
- Git and change-management restrictions.

This file is authoritative for project-specific security policy.

### CODEX.md

Status: IMPLEMENTED

Purpose:

Maintains the repository map, component responsibilities, and
architectural reference.

Must be updated when files or responsibilities change.

### PROMPT.md

Status: IMPLEMENTED

Purpose:

Defines the initial project objectives, required functionality, and proposed
architecture. It is planning input, not evidence that planned components are
implemented.

### README.md

Status: IMPLEMENTED (foundation documentation; complete user guide still planned)

Purpose:

Primary user documentation. Currently describes the implemented libraries,
development commands, security boundaries, and unfinished application features.

Should cover:

- What ssmh does.
- Installation.
- AWS prerequisites.
- Authentication.
- IAM role assumption.
- Interactive sessions.
- Remote commands.
- Instance discovery.
- Port forwarding.
- Troubleshooting.
- Security considerations.
- Known limitations.

Only document functioning capabilities as available.

### LICENSE

Status: PLANNED

Purpose:

Defines licensing terms.

The license must be selected by the project owner.

Codex MUST NOT invent or select a license without authorization.

### Makefile

Status: IMPLEMENTED (build, release, verify-release, test, race, lint, security, clean)

Purpose:

Standardized development and release commands.

Expected targets:

    make build
    make test
    make lint
    make security
    make clean
    make release
    make verify-release

### go.mod / go.sum

Status: IMPLEMENTED (module and pinned checksums; release dependency review pending)

Purpose:

Go module definition and dependency verification.

Use AWS SDK for Go v2.

Avoid unnecessary dependencies.

The Go module path is `ssmh`, matching the local project directory. `go.mod`
requires patched Go 1.27.2 and pins reviewed SDK v2 components. `go.sum` is
generated by Go tooling and the modules have been verified offline.

Do not invent a GitHub organization or remote repository URL.

### .gitignore

Status: IMPLEMENTED

Purpose:

Excludes local and generated artifacts, including Go build and coverage output,
caches, temporary files, logs, local credentials, secrets, and editor or
operating-system state.

Must account for:

- dist/
- Temporary files.
- Coverage output.
- Local debug logs.
- Editor-specific files.
- Local credential or secret artifacts.

Must not exclude source code or project documentation.

### .golangci.yml

Status: PLANNED

Purpose:

Configuration for optional static analysis and linting.

Security-sensitive warnings should not be disabled merely to
produce a clean build.

---

## 5. Application Entry Point

### main.go (repository root)

Status: IMPLEMENTED (plain `go build` entry point)

Thin `os.Exit(app.Execute())` wrapper. Produces `./ssmh` with ordinary root
`go build`; static release flags remain owned by the Makefile. No separate
authentication, signal registration, error formatting or session lifecycle.

### internal/app/execute.go

Status: IMPLEMENTED (shared process boundary)

`Execute` owns top-level signal cancellation (including controlled SIGPIPE),
invokes CLI Run with process arguments/streams, reports the returned safe error
and maps its exit code after CLI cleanup. Both executable entry points delegate
here. It imports CLI and standard process packages, never transport directly.
Existing cmd executable subprocess tests now exercise this shared implementation,
including help/version, redacted usage errors, offline credential isolation and
broken-output-pipe behavior.

### cmd/ssmh/main.go

Status: IMPLEMENTED (thin wrapper over shared app process boundary)

Purpose:

Conventional cmd application entry point; delegates to app.Execute. Its private
execute function preserves the subprocess-test boundary without separate logic.

Responsibilities:

- Initialize the application.
- Invoke CLI processing.
- Establish top-level cancellation handling.
- Convert application errors to process exit codes.

Must remain small.

Business logic must not accumulate in main.go.

---

## 6. CLI Package

Current files: `flags.go` and `flags_test.go` implement/test parsing and option
validation. `root.go` and `connect.go` add native-shell orchestration through
SDK/channel/terminal test boundaries; the implemented list/check/output/forward
files are described below.
`diagnostics.go` and `diagnostics_test.go` implement/test fixed stage reporting,
debug durations, opt-in identity, no stdout contamination, failure cleanup and
bounded diagnostic pipes. Remote command result propagation still requires no
local diagnostic or cleanup error; reporting failure cannot mask local failures.
`api_diagnostics_test.go` additionally exercises the debug-only SDK summaries with
real SDK configuration, signing and retry behavior at a synthetic HTTP boundary.
`native_command_tls_test.go` opts into OS loopback TLS via SSMH_TEST_TCP=1 and
composes real CLI parsing, isolated synthetic SDK provider selection/signing,
EC2/SSM document/session APIs, production native Connect, encrypted challenge,
command.Run stdout/stderr/typed status and fresh owned termination. Only network
routing/replies are synthetic; no custom service endpoint or production bypass
is enabled. Plain/encrypted status 37, KMS denial, corrupt ciphertext, missing
status, cleanup denial and WebSocket HTTP 403 refusal are covered, with joined synthetic peers and fixed
secret-free errors. Independent standard GCM generates/authenticates peer
payloads; existing native codec tests cover independent framing. This is an
in-process CLI composition test, not a compiled executable, PTY or live AWS test.
The same file's TestNativeShellTLSComposition runs the production terminal loop
against a document-owned non-KMS TLS peer with pipe input. Default StartSession
DocumentName stays omitted; first ordered output establishes readiness without
an invented handshake. ANSI/UTF-8 output and input/Ctrl+C/one EOF Ctrl+D are
preserved. Normal owned close, transport loss and cleanup denial all exercise
owned termination; HTTP 403 also fails before terminal readiness. Denied upgrades
emit no application bytes, reveal no response body and make no KMS request;
owned termination still runs with a fresh context. Failures never become successful EOF. It proves local composed
pipe behavior, not physical TTY controls, resize/restoration or remote apps.
`native_executable_tls_test.go` builds/runs the actual cmd/ssmh binary under the
same SSMH_TEST_TCP opt-in. A private CONNECT proxy permits only selected regional
EC2/SSM/ssmmessages/KMS host:443 requests and tunnels exclusively to the local
synthetic TLS service. The child has explicit fake environment credentials,
/dev/null shared config/credentials, disabled IMDS, an owner-only temporary public
test CA and explicit proxy; no inherited app environment, endpoint override or
disabled TLS verification. Private TLS keys stay in memory. All eleven command/
pipe-shell cases also exercise real process exit codes/top-level diagnostics and
fresh owned cleanup, with signed fake identity/service/region assertions. Proxy
admission closes before joining relay workers; sockets have twelve-second bounds.
This is compiled native-host local integration, not live AWS, ARM64 execution or
a physical TTY/app test. It uses ordinary supported production proxy/CA settings;
no production test hook/backdoor is added.
Its offline isolation test verifies build settings exclude host credentials,
profiles, proxies/loader/overlay flags, while preserving trusted tooling/cache
paths. Builds are cached/offline/read-only and child app credentials/config are
explicit. Signed-host checks reject bare names, wrong regions and spoofed suffixes.
They now also compose noninteractive commands via command.SerializeShell,
ssm.StartCommand and command.Run. Dependencies.connect receives the
explicit session type. Typed commandExit is mapped only when it is the sole
error leaf; local/AWS cleanup failures cannot be masked by remote status.
`root_test.go` verifies routing without authentication, owned cleanup at failure
stages, independent cleanup contexts after cancellation/duration, request
preservation, setup-budget separation, platform rejection and redacted failures.
It also composes the real terminal Run with a synthetic authenticated channel.
`cmd/ssmh/main_test.go` checks executable-style help/version, exit codes, stream
separation and sensitive argument redaction through subprocesses. The shared app process boundary
registers SIGPIPE to prevent broken inherited output pipes from terminating the
process before deferred owned cleanup; a broken-help-pipe subprocess test verifies
the controlled write-error path.
Unimplemented modes are explicitly rejected before AWS calls. Parser failures do not echo supplied
values, so malformed MFA or other sensitive arguments cannot enter diagnostics.
Grouped boolean short options and attached short-option values are supported;
normalization is bounded and preserves command argument bytes.

Native forwarding is composed in connect.go, sharing selected SDK authentication,
complete Linux/Online registration, setup/lifetime deadlines, MFA disablement,
opt-in identity/metrics/trace reporting and fresh owned AWS cleanup. It reserves
the exact TCP4 loopback port before authentication, then calls StartForward,
ConnectForward and ServeForward. No terminal Run/command/input path is used.
Default forwarding diagnostics use bounded private stderr, report address/target
after readiness and do not add STS identity calls; quiet suppresses information.
forward.go supplies onceForwardListener cleanup ownership and serveNativeForward,
which joins native shutdown even on pre-serving validation rejection. Listener
closure precedes AWS cleanup on post-Start failures; no shell/plugin fallback.
forward_test.go covers both documents/host/IPv6 preservation, no terminal/input,
identity options, quiet/verbose/debug separation, all setup/serving/cleanup
failure stages, setup/duration/cancellation, MFA disablement, broken default
readiness-report pipes with owned cleanup, and real native
adapter rejection/true-nil cleanup. These synthetic boundaries do not prove OS
TCP binding or live AWS interoperability.

Directory:

    internal/cli/

Purpose:

Owns command-line parsing, validation, and user interaction.

Files:

### root.go

Root command and application initialization.

Implemented routing includes read-only list/check/JSON through list.go/check.go;
shell/command/forwarding accept an ID or exact Name. Plugin requests remain explicitly refused.

### connect.go

Native shell/command/forwarding lifecycle, document preflight where required and
owned-session cleanup. Forwarding uses fixed AWS-managed documents and strict
authenticated Port negotiation rather than shell document reads.
EC2 Query validation precedes authentication. Selected-config resolution and
running-state validation share the setup deadline and precede session-control
client construction. Only the validated unique ID reaches SSM requests and
connection diagnostics. Duplicate Names include stopped matches, not just eligible
instances; failures close any pre-reserved forwarding listener and HTTP pool.
`resolution_test.go` covers ID/literal Unicode Name selection in all four session
modes, exact escaped filters/all-page resolution, selected profile/role config,
resolved-ID-only SSM requests/diagnostics, stopped/ambiguous/malformed/later-page
failures, cancellation and listener/HTTP cleanup. `api_diagnostics_test.go` also
composes actual signed SDK EC2 XML pagination by Name through SSM Start/Terminate
with a synthetic HTTP boundary; it is not live interoperability evidence.

### diagnostics.go

Implemented fixed lifecycle stage reporting, validated opt-in caller identity,
debug stage/API durations, SDK retry-loop counts and private cancellable diagnostic writes. No raw SDK
requests, errors or remote payloads are accepted as diagnostic fields.
Verbose/debug fixed termination reasons report local cancellation/deadline/duration,
setup or operation/reporting failure, or successful operation return without
inventing remote completion. Lifetime state is snapshotted before deferred local
cancellation; caller state is captured before the independent cleanup budget.
Reporting follows owned AWS cleanup and never masks independent
cleanup failure; default/quiet and read-only list/check have no termination report.
Diagnostics tests verify classification/redaction, cleanup-before-report and
normal-versus-duration cancellation snapshots across the shared session lifecycle.

### list.go

Implemented read-only EC2/SSM inventory join and list lifecycle. Separate API
boundaries cannot start sessions. Defaults to running plus SSM Online, preserves
exact filters/selected config and emits only after complete validated inventories.
Colocated tests include actual SDK serialization and synthetic joins, not live AWS.

### check.go

Implemented read-only prerequisite checks and human/JSON reports. Resolves ID or
exact Name, EC2 running, Linux/SSM Online and default native shell-document
compatibility. Optional-denied STS metadata does not change the selected identity;
all other identity failures fail. Reports do not claim session permissions or live
channel connectivity. Uses separate read-only client interfaces and no session start.
`check_test.go` verifies exact Name/ID resolution, all prerequisite failures,
no session-control construction, preserved selected config after explicit STS
metadata denial, cancellation, broken output and MFA/HTTP cleanup. Actual signed
SDK STS/EC2/SSM requests use synthetic HTTP fixtures, never live AWS credentials.

### forward.go

Implemented CLI once-only listener owner and native serving adapter. Main
forwarding lifecycle orchestration shares connect.go; forward_test.go tests it.

### flags.go

Shared CLI argument definitions.

### output.go

Implemented listing table and ASCII-only JSON formatting with seven explicit
allowlisted fields; ASCII encoder is shared with check's private report DTO.
Human Names/profile are sanitized; decoded JSON preserves Unicode.

Responsibilities:

- Parse CLI arguments.
- Validate mutually exclusive options.
- Select requested operation.
- Present errors.
- Preserve stdout/stderr separation.
- Delegate AWS and transport operations.

Security requirements:

- No credential logging.
- No local shell interpolation.
- No implicit privilege escalation.
- No ambiguous target selection.
- No secret exposure in help or debug output.

The CLI package should not directly implement AWS protocol
or terminal transport behavior.

---

## 7. Configuration Package

Current files: `config.go`/`config_test.go` and `kms.go`/`kms_test.go`. Invocation
validation is in config.go and literal KMS key/region policy in kms.go;
`validate.go` below is planned. Region resolution does not invent a
default. `ForwardTarget.Validate` rechecks exported fields at listener/native
resource boundaries without DNS or normalization; Address returns only loopback.
`forward_target_test.go` tests direct construction and parser agreement. Fuzz seeds cover forwarding
parsing; native protocol fuzz targets live in `internal/transport/native`.

Forwarding-parser and stream-endpoint-validator fuzz runs pass. `govulncheck` is
available through a private /tmp tool installation. Its earlier Go 1.27.1 scan
reported eight reachable standard-library vulnerabilities fixed in Go 1.27.2.
go.mod now requires Go 1.27.2 to prevent builds with that vulnerable toolchain;
the patch uses supported Go toolchain selection without disabling checksums or
changing service dependencies. The Go 1.27.2 rescan reports no vulnerabilities;
Go 1.27.1 with GOTOOLCHAIN=local refuses the module before building. These checks
do not certify live behavior or replace release review. Validation status is in
docs/development.md.
Network access now permits normal SDK module downloads; the EC2 SDK
is pinned and implemented through read-only discovery/listing/check and connection
Name/state validation. Native
transport uses the standard library and terminal controls use cached x/sys.
`/snap/go/current/bin/go` works directly; the `/snap/bin/go`
launcher currently fails its confinement capability check.

Directory:

    internal/config/

Purpose:

Represents validated application configuration.

### config.go

Defines internal configuration structures.

Potential fields:

- Instance identifier.
- AWS profile.
- Region.
- IAM role ARN.
- Session name.
- External ID.
- Session document.
- Session reason.
- Connection timeout.
- Session duration.
- Backend selection.
- Logging mode.
- Port-forward configuration.

### validate.go

Validates configuration values and option combinations.

Examples:

- Required instance for connect operations.
- Valid port ranges.
- Unsupported backend combinations.
- Invalid duration values.
- Conflicting command options.

Configuration validation must occur before security-sensitive
network operations whenever practical.

Never persist credentials in configuration structures intended
for serialization.

---

## 8. AWS Authentication Package

Current files: `client.go`, `credentials.go`, `identity.go`, `metrics.go` and their colocated tests. Credential loading, explicit
AssumeRole, and HTTP endpoint guards are currently combined in `client.go`.
Other named files below remain planned. Tests exercise environment/profile
selection, region precedence, role parameters, cache refresh, MFA refresh,
failed role assumptions, and refusal of signed requests to insecure endpoints.
`sso_test.go` verifies the actual SDK token provider with synthetic refresh API/cache
fixtures: successful cache rewrite preserves 0600, failed refresh preserves cache
and returns no token, and missing/unrefreshable login does not contact the token API.
This documents existing provider behavior, not an application-owned credential file.

Authentication modules are now config v1.32.19 and credentials v1.19.18, the
reviewed patch introducing restricted new login-cache creation. Load explicitly
sets SDK RestrictFilePermissionsUserReadWrite; inherited unrestricted mode cannot
weaken it. SDK-created login files use 0600, while existing file permissions
remain unchanged and must be secured separately. No application credential store,
cache repair or login subprocess is introduced. `login_cache_test.go` exercises
actual SDK login-profile resolution and the configured policy, SDK refresh with
synthetic API/cache fixtures, owner-only replacement-file creation, preserved
existing permissions, missing/failed refresh and redacted invalid settings.
Synthetic DPoP text is not a private key; fake refresh never executes signing
options or contacts AWS. Required dependency updates are STS v1.42.2, SSO OIDC
v1.36.1, SSO v1.30.18, IMDS v1.18.24 and Signin v1.1.0, plus SDK internal/v4a
v1.4.25. Their changelogs introduce endpoint/auth support, not a new application
identity or API workflow. Core/EC2/SSM/Smithy/x/sys pins remain unchanged; latest-
version inventory is reviewed separately and is not a blanket upgrade approval.

Custom CA support is implemented through the SDK's BuildableClient resolver:
AWS_CA_BUNDLE takes precedence over the selected shared ca_bundle, with SDK PEM
loading/failure semantics. A pre-resolution Proxy-selection guard checks signed
destinations and rejects redirected requests before transmission on every builder
copy. It delegates valid original requests to the configured/environment proxy.
Captured SDK credential/default-mode clients use HTTP/1.1 without keepalives,
because those builder copies expose no explicit idle-pool cleanup. The returned
application client owns a separate guarded, redirect-refusing pool with resolved
TLS roots, 30-second request/15-second header budgets and ordinary idle cleanup.
Native sockets inherit these roots/proxies. CA selection does not authorize new
service endpoints or disable hostname/certificate verification. Explicit custom
roots replace system defaults as the SDK does; include every required trust root.
SDK CA file reads/PEM parsing remain SDK-managed, not application-size-bounded.
ca_test.go covers environment/profile precedence, malformed/missing CA failure
redaction, builder-copy guards, all redirect classes and proxy delegation; real
in-memory TLS verifies accepted roots and rejects unknown roots/wrong hostnames
before HTTP authentication bytes are transmitted. No real proxy/live AWS proof.

Directory:

    internal/aws/

Security classification: CRITICAL

Purpose:

Centralizes AWS SDK configuration and authentication.

### client.go

Constructs AWS SDK client configuration and service clients.

### credentials.go

Implemented bounded read-only `CredentialSources` classification from SDK numeric
provider-source metadata. No credential retrieval, raw string/object inspection,
extra network requests, profile paths or endpoints are exposed. Unknown metadata
returns unavailable. Standard credential resolution remains in `client.go`.

### assume_role.go

Implements explicitly requested STS AssumeRole operations.

### region.go

Resolves the selected AWS region.

### identity.go

Implemented `ReadIdentity` through SDK STS GetCallerIdentity. Private `Identity`
fields expose only validated matching account and principal ARN, not UserId or
credential material. API/validation failures return no partial identity; no
different credentials are tried. Tests cover malformed metadata, partitions,
cancellation and SDK failure redaction. This is not an IAM session-permission check.

### metrics.go

Implemented bounded debug-only SDK operation observation. `WithAPIMetrics`
preserves context control while supplying a collector to `Load`; Debug enables
the middleware before SDK credential resolution. `APIMetric` exposes only private,
allowlisted labels, duration, success and optional SDK attempt count. `Drain`
transfers bounded summaries with an overflow flag. Middleware performs no I/O,
does not change results/errors, and never retains sensitive SDK objects. Credential
SDK clients share the capture; only reviewed EC2/STS/SSM operation pairs are recorded.

Responsibilities:

- Load AWS profiles.
- Support IAM Identity Center credentials.
- Support default credential providers.
- Assume explicitly requested roles.
- Preserve temporary credential refresh.
- Construct authenticated AWS clients.
- Handle authentication failures safely.

Security boundaries:

- Never expose secret credentials.
- Never persist temporary credentials.
- Never downgrade authentication.
- Never silently change AWS identity.
- Never bypass role-assumption failures.

Other packages should receive configured AWS service clients
rather than reimplementing credential resolution.

---

## 9. EC2 Discovery Package

Directory:

    internal/ec2/

Purpose:

Identifies the intended EC2 target.

Implemented: `discovery.go` and `resolver.go` with colocated offline tests.
`API` exposes only DescribeInstances; `Query` uses exact case-sensitive predicates
combined with AND and unique tag keys (at most 50 total filters). AWS wildcard
characters/backslashes in values are escaped, escaped values are bounded to 255
characters and responses are locally rechecked.
`Instance` retains only ID, Name, known state, optional canonical IPv4 and caller
region; Name remains untrusted display text and must be sanitized. Metadata/tag
controls, duplicate keys/IDs, unknown states and malformed addresses fail closed.
Discover requests MaxResults=100 and uses the instance-id filter rather than
InstanceIds, which AWS forbids combining with MaxResults. Local limits are 1000
pages, 1000 reservations/instances per page, 10000 total instances and 8192-byte
opaque pagination tokens. Empty pages continue; cycles/later failures discard all
results. These bounds apply after SDK decoding. The selected client determines
credentials/endpoint, so the caller must supply its matching region label.
Query.Validate exposes pre-authentication syntax/limit checks to CLI listing.
Resolve returns ErrNotFound/ErrAmbiguous without echoing untrusted metadata and
never picks a running/Online duplicate over another exact-name match. SSM joins and
CLI listing/check and connection Name/state validation are implemented; live EC2
verification remains pending.

### discovery.go

Lists EC2 instances and associated metadata.

### resolver.go

Resolves instance IDs and EC2 Name tags.

### instance.go

Planned separate file; the implemented Instance DTO currently lives in discovery.go.

Responsibilities:

- Resolve instance identifiers.
- Search Name tags.
- Detect duplicate names.
- Retrieve instance state.
- Retrieve private IP addresses when needed.
- Support pagination.
- Apply discovery filters.

Security requirements:

- Never select ambiguous targets silently.
- Treat EC2 metadata as untrusted strings.
- Escape unsafe terminal formatting in metadata.
- Never modify EC2 resources during discovery.

This package must remain read-only.

---

## 10. SSM Package

Current control files: `session.go`, `shell.go`, `forward.go`, `status.go`, `availability.go` and their colocated tests.
Command document preflight is in `documents.go` and `documents_test.go`.

ValidateShellDocument in shell.go is now the read-only default-version compatibility
preflight shared by StartShell and CLI check. It validates context/client/name,
checks cancellation before/after GetDocument and keeps the existing strict schema,
active Session-document and literal KMS-key boundary. StartShell alone starts ownership and
grants optional-handshake capability; successful validation alone grants none.
`API` is the session SDK boundary; `DocumentAPI` is the read-only GetDocument
boundary. Shell and command invocations require document reads. `documents_test.go`
tests bounded parsing, non-elevated/separate-output properties and read failures.
`Start` grants ownership only for a successful AWS response with a valid session
ID; `Terminate` is concurrency-safe and retryable after failure; `Online` checks
paginated registration without starting a session. `TransportMaterial` is the
explicit token boundary for backends. `OwnedContext` exposes only live owned
session/target/region for private KMS context binding, no transport secrets or
document/credential authorization; session_test.go tests lifetime/immutable target.
`StartShell` alone enables the private
non-KMS shell capability exposed read-only by `HandshakeOptional`; ordinary
`Start` always requires a handshake. Terminated sessions cannot authorize it.
`DocumentKMSContext` exposes only the literal key/session type authenticated by
StartShell or StartCommand, clearing both after successful owned termination.
ShellKMSKey remains a shell-only projection; command capability cannot authorize
a shell, and ordinary Start grants no encryption capability.
Other files below remain planned.

Directory:

    internal/ssm/

Security classification: CRITICAL

Purpose:

Manages AWS SSM API operations and session ownership.

### client.go

SSM API client wrapper and interfaces.

### session.go

Session creation and session metadata.

### lifecycle.go

Session lifecycle and cleanup management.

### documents.go

Implemented read-only validation of selected noninteractive command documents;
exact root/parameter/Linux property names and typed empty separators prevent
case/null policy ambiguity. Cancellation before/after GetDocument fails closed;
unit and CLI regression tests prove invalid documents never start a session.
StartCommand validates target/region and one bounded UTF-8 non-NUL command
parameter, reads the selected document before StartSession and retains its literal
KMS key with NonInteractiveCommands type. Shared sessionInputKey in shell.go
validates recognized preference names without rewriting server-owned values.
Missing command inputs select no KMS; present null/invalid/unknown/parameterized
inputs fail closed, and key ARNs must match region/partition. Tests cover key
selection, cross-region/type isolation, capability lifetime and cleanup failure.
ValidateCommandDocument remains a read-only syntax/policy check without a selected
region or ownership capability; StartCommand adds selected-region validation.
other document/session capabilities remain planned.

### shell.go

Implemented `StartShell` preflight/ownership boundary for shell preferences. The
bounded duplicate-rejecting parser requires exact recognized document/input
keys, Standard_Stream and literal supported KMS key or no selection. Key ARNs
must match the region/partition before StartSession. `ShellKMSKey` exposes the
key only on that live document-owned shell and clears on termination; ordinary
Start grants none. KMS never grants HandshakeOptional. ValidateShellDocument now
takes region; read-only CLI check shares validation without starting KMS/session
operations. Logging/run-as/timeouts and
shell profile remain unchanged and AWS/agent-enforced. Tests cover document
selection, malformed/ambiguous/encrypted documents and capability lifetime.

### forward.go

Implemented StartForward validates instance/region/reason/exported destination,
selects exactly AWS-StartPortForwardingSession or its ToRemoteHost counterpart,
and creates fresh canonical singleton port parameters plus unchanged host only
for the remote-host mode. No custom document, shell, default port, local DNS or
listener is used. It delegates response validation/ownership/cleanup to Start;
successful ownership is retained when cancellation races with the response.
The returned session still requires strict authenticated Port negotiation and
caller-owned termination. Fixed AWS-managed documents need no GetDocument here;
the native handshake checks exact properties and refuses KMS/unsafe types.
forward_test.go covers both modes/IPv6/host preservation, validation/cancellation,
redacted failures, malformed-response cleanup and actual SDK signed request/
response/termination serialization using synthetic HTTP. No live AWS or CLI
forwarding proof is claimed.

### status.go

Implemented read-only `Inventory` through `StatusAPI`. It retrieves EC2 SSM
registration only, preserves known Online/ConnectionLost/Inactive statuses and
Linux/Windows/macOS platforms, validates optional numeric agent versions, and
returns deterministic bounded `Status` records. It does not expose arbitrary
SDK response metadata or mistake SSM ComputerName/IPAddress for EC2 Name/private
IP. Nil/oversized pages, unknown metadata, duplicate IDs, pagination cycles,
cancellation and later API failures return no partial result. The SDK performs
response decoding before these checks; these are not a transport-body size limit.
`status_test.go` covers query/pagination, actual SDK request serialization and
response decoding with a synthetic HTTP client, validation, cancellation,
redacted errors and safety limits; metadata parsing has a fuzz target. Listing/check
CLI composition is implemented; live AWS validation remains pending.

### availability.go

Implemented `Online` through the narrower read-only `StatusAPI`. Requests a single
validated InstanceIds filter with 50-row pages and inspects all pages (including
empty pages) before accepting exactly one Online EC2 registration. Reuses inventory
metadata validation; unknown platform/ping/resource/agent version, unexpected or
duplicate IDs, cycles, oversized tokens/pages, cancellation and later errors
return no partial record. Success exposes only ID/resource/ping/platform/agent
version, not arbitrary SDK Name/IP/hostname fields. Bounds are 1000 pages and
8192 token bytes; SDK decoding precedes checks. Readiness is not EC2-state or
StartSession authorization proof. CLI still requires Linux after this check.
`availability_test.go` covers complete targeted pagination, ambiguity, later
failures, unknown metadata, bounds, pre/post-request cancellation, safe field
selection and actual SDK serialization/signing/decoding through synthetic HTTP.
`cli/availability_test.go` proves a valid first row followed by a duplicate or
API failure never reaches StartSession and does not expose tokens/raw causes.

Responsibilities:

- Check SSM registration.
- Determine agent availability.
- Start sessions.
- Track session ownership.
- Terminate owned sessions.
- Manage session metadata.
- Validate document selection.

Security requirements:

- Never expose SSM tokens.
- Never terminate unrelated sessions.
- Never silently change session documents.
- Never bypass IAM authorization.
- Never leak authenticated stream URLs.

This package manages session control operations.

It must not become responsible for raw terminal rendering.

---

## 11. Transport Package

Directory:

    internal/transport/

Security classification: CRITICAL

Purpose:

Provides the communication backend for SSM sessions.

### transport.go

Defines the interface shared by transport backends.

Possible responsibilities:

- Connect.
- Send.
- Receive.
- Close.
- Report capabilities.
- Handle session termination.

Transport capabilities must be explicit.

Do not assume every backend supports every session type.

---

## 12. Native Transport

Current files: `message.go`, `mux.go`, `mux_state.go`, `protocol.go`, `encryption.go`, `kms_protocol.go`, `kms.go`, `port.go`, `forward.go`, `control_json.go`, `websocket.go`, `stream.go`, `trace.go`, and their
colocated tests. Other listed files remain planned.
The fixed prefix is 120 bytes, the encoded header length is 116, and payloads
are bounded to 1 MiB before copying. Decode checks known types, schema, lengths,
sequence and flags, UUID metadata, and SHA-256 payload integrity. Publication
notifications have a narrow empty-payload exception for an unused zero digest.

`Protocol` is driven by a single event loop and accepts the exactly requested
shell/command type or Port through explicit-destination ConnectForward setup.
Ordinary NewProtocol/unverified Connect refuse unsupported/KMS actions and pre-handshake
application data except first ordered Output for an owned document-verified
non-KMS shell; no timer/CLI downgrade exists. It validates acknowledgement identity and sequence,
orders/deduplicates output, caps windows at 64 frames and the incoming reorder
buffer at 1 MiB, and permits at most five retransmissions with unchanged UUID
and sequence. It never creates replacement sessions or restarts a remote command.
It supports publication pause/start and validates channel-close session ownership.
No live interoperability has been tested yet.

Unverified KMS refusal returns a fixed error requiring document-owned shell/command
capability, never recommends this client's
unavailable plugin backend, and never echoes requested key/context values. The
unsupported action remains status 3 with no key or challenge acknowledgement;
legacy and random-context handshake tests verify ACK/response ordering, no
readiness/output/input, and permanent rejection of later completion/challenge/
plaintext. Authenticated TLS tests cover both forms through Connect and the
document-authorized non-KMS shell capability, with redacted diagnostics/trace.
Document-owned KMS shells/commands are now composed through Connect as described below;
live encrypted AWS interoperability remains unverified. The protocol guide
pins agent f397c74d46f99d78244a2bcb469bb86729672ff9: required context challenge
acknowledgement and aws:ssm:RandomChallenge binding are a separate prerequisite
from the later encrypted challenge. Reviewed plugin snapshot 7cde6748 lacks those
handshake fields and cannot satisfy that agent requirement as written; this is
not a statement about all installed versions or the local agent setting.

`encryption.go`/`encryption_test.go` add the private single-owner sessionCipher
payload codec. Exactly 64 caller-owned key bytes become directional AES-256 GCM
states: first half decrypts agent data, second encrypts client data. Equal halves
are refused as an additional reflection defense, not an AWS framing rule.
Go's NewGCMWithRandomNonce implements the AWS 12-byte nonce prefix/16-byte tag
without manual nonce slicing. Ciphertext is bounded to MaxPayload including the
28-byte overhead, and client encryption is limited to 2^32 messages per key.
Nil/cleared handles, malformed lengths, quota exhaustion and failed authentication
return fixed errors and deactivate both directions without partial plaintext.
Formatting pointer/value handles redacts keys and payloads; outputs do not alias
inputs. Caller key buffers are not modified/retained and remain caller-owned;
clear releases key-schedule references, not guaranteed erasure of crypto/Go
memory or returned copies. No SDK request, credentials, file or CLI feature is
added by the codec alone. Connect now uses it for document-owned KMS shells/commands,
not unverified sessions or forwarding.
Tests use independently composed standard-GCM AWS wire fixtures, a published Go
AES-256 vector, corruption of every nonce/ciphertext/tag byte, direction/reflection,
key/payload bounds, caller-buffer clearing, quota, fresh nonces and fuzzing.
These validate the codec, not AWS KMS or a live encrypted session.

`kms_protocol.go`/`kms_protocol_test.go` integrate that codec into a private
encrypted Protocol constructor with a one-shot key-preparer boundary. Exact
document-selected key equality and canonical optional 16-byte context challenge
are checked before preparation; unknown/mismatched/duplicate actions prevent the
callback regardless of action order. Provider failures/invalid cipher or bounded
empty/oversized key ciphertext return fixed errors and release partial keys.
Successful response carries the key ciphertext and context acknowledgement;
the preparer contract requires actually binding that challenge, not merely
claiming support. A decrypted 64-byte agent challenge is re-encrypted in the
opposite direction before HandshakeComplete can establish readiness. Ordered
Output/StdErr/ExitCode decrypt; outgoing Output encrypts once, resize/control do
not. Replay stamps retain original ciphertext; retransmits retain the nonce,
UUID and sequence without consuming new encryption quota. An immutable
requiresEncryption flag survives key-reference cleanup, preventing plaintext
downgrade. Protocol failure, owned close, retry exhaustion and channel shutdown
release cipher/preparer references; channel shutdown also ends protocol reuse.
Tests cover synthetic legacy/current handshakes, independent challenge/data
decryption, invalid actions/preparation, readiness failures, ordering/replays,
retransmission, in-memory encrypted channel exchange, joined shutdown and
release-without-downgrade; parameter parsing also has a fuzz target. Ordinary
NewProtocol/unverified sessions still refuse KMS. Connect supplies StartShell/StartCommand's
authenticated document/key capability and establishment/lifetime cancellation;
synchronous preparation stalls the protocol owner
and ACKs are returned only after it completes. No live KMS proof is asserted.

`kms.go`/`kms_test.go` implement private SDK v2 GenerateDataKey preparation with
selected credentials/region/HTTP/API configuration, no credential-chain reload,
endpoint overrides or SDK payload logging. KMS v1.53.0's reviewed endpoint-rules
change and required shared SDK pins match existing dependencies; no unrelated
upgrades. Live owned session target/region must match selected config. Key IDs,
multi-region IDs, aliases and matching regional commercial/China/GovCloud ARNs
are validated; returned key ARN must match an explicit key or selected alias's
account. Signed KMS responses resolve aliases; authorized alias administrators
remain trusted. No DescribeKey/identity probe. The one-use callback requests
64 bytes with aws:ssm:SessionId/TargetId and optional RandomChallenge, bounded to
five seconds plus parent cancellation. Partial/error/canceled/terminated/invalid
responses return no cipher/blob and fixed errors; SDK Plaintext is cleared on
every response path. Returned ciphertext is an independent 1–6144-byte copy,
not recipient ciphertext. SDK/Go/crypto memory erasure is not guaranteed. Mock
and signed SDK JSON tests use synthetic HTTP, never live credentials/KMS.
Connect now supplies authenticated type-bound document selection and its setup/lifetime
context. `ssm.Session` retains validated StartSession target/region;
`OwnedContext` returns only live owned session/target/region under its lock, no
token/URL or document/credential authorization. Nil, zero and terminated sessions
grant no context. Later concurrent termination can race the snapshot; request
lifetime cancellation and post-request ownership recheck remain necessary.

`config/kms.go` centralizes key/alias/ARN syntax and region/partition validation
for document and native boundaries, with colocated tests. `kms_connect_test.go`
composes real StartShell/StartCommand ownership, selected SDK key generation and TLS/SigV4/
token/challenge/channel exchange at in-memory boundaries. Success, key mismatch
(no key API call), early completion, KMS denial/setup cancellation and plaintext
rejection are covered for both modes; encrypted command stdout/stderr/typed exit
status are verified. CLI shell_test.go/command_test.go verify capability/config
forwarding, selected document preservation, command result 37 and owned cleanup
on success/setup failure. The command capability cannot grant shell/no-handshake
readiness. No live AWS proof. Port still refuses KMS;
key expressions/Parameter Store selection remain unsupported.

`mux.go`/`mux_test.go` implement the private smux version-1 inner forwarding codec,
not a Port channel or listener. Eight-byte little-endian headers precede bounded
uint16-sized bodies; incremental feeds retain one partial frame and transfer
completed bodies without input/later-frame aliasing. Unknown commands/versions,
malformed controls/IDs and truncated EOF fail permanently; consumer errors and
formatting reveal no application data. Per-feed bounds reuse MaxPayload; caller
backpressure is applied by ServeForward rather than buffered inside the decoder.
Tests cover independent wire bytes, fragmentation, bounds, malformed/truncated
input, lifetime, ownership/redaction and fuzzing. `docs/native-forwarding.md`
records AWS/smux references and outstanding forwarding gates. CLI forwarding is
now wired through this native stack; no extra dependency or public bind is added.
`port.go` now adds `ConnectForward` for a validated explicit destination on an
owned session. Its private protocol constructor requires a full Port handshake,
agent version strictly greater than 3.1.1511.0, exact host/local/remote port
properties and TCP LocalPortForwarding. Unknown/ambiguous properties, Unix socket
selection and KMS fail closed. The fixed Port wire compatibility level 1.2.339.0
is distinct from ssmh's release version and selects mux without agent keepalives;
both OpenDataChannel and the response use it. Shell/command paths now share this
fixed numeric compatibility level instead of ssmh-dev, covering the agent's
separate-output version checks without claiming to be the official plugin.
Protocol tests assert its literal value for all shell/command types; real TLS
OpenDataChannel and handshake-free shell fixtures plus streaming handshakes check
matching advertisements. Build/linker version metadata cannot select wire
features; KMS/type/readiness/ownership validation is unchanged.
Binary Output and a validated global destination-error Flag are
delivered separately; terminal payloads and invalid flags are refused. Local
input supports binary chunks or the four-byte terminate flag, never resizing.
`ConnectForward` owns the encrypted channel only, not sockets/listeners or AWS
cleanup. CLI lifecycle integration is implemented; live validation is unfinished.

`forward.go` implements `ServeForward` orchestration for an established Port
Channel and caller-created listener matching the requested 127.0.0.1 TCP port.
Successful validation transfers channel/listener ownership once; rejection leaves
cleanup with the caller. One owner drives mux state; at most 64 accepted/pending
connections have paired socket workers. The 128-frame serialized send queue reserves
64 FIN slots and stops data/accept admission at 64, applying reader backpressure.
Frames are sent as contiguous 1024-byte SSM chunks with no retry on a new stream.
Each local output queue holds four bounded inner frames; per-inner-frame
transmission, local writes and per-outer-frame delivery waits have ten-second
budgets. No inner keepalives, terminal I/O or logging
is generated. Local/peer EOF performs full close, peer EOF after queued local output
delivery; no independent end-to-end TCP half-close is promised. Destination-error
flags stop the whole session rather than invent a stream identity. Failures,
cancellation and owned EOF join workers and close listener/connections/channel;
cleanup failures are redacted but retained. Only exact local channel shutdown
cancellation leaves are suppressed. Active/truncated streams cannot yield normal
EOF. CLI forwarding lifecycle wiring is implemented; live interoperability
remains unverified.

`mux_state.go`/`mux_state_test.go` add the private single-owner client stream
lifecycle above the codec: at most 64 active streams, monotonic odd IDs starting
at 3 with no wrap/reuse, bounded 32768-byte outgoing chunks and one local FIN.
Peer FIN delivers one receive EOF without closing the local send direction;
post-FIN data, unsolicited opens and never-issued/even IDs fail the whole state.
Late data/FIN on issued locally closed IDs is discarded, matching upstream close
races without retaining unbounded retired-ID history. Delivery transfers bytes
without buffering/logging; callback failure, malformed input and truncated/open
stream completion fail closed and release state. Shutdown opens/closes no sockets
and cannot perform AWS cleanup; forward.go now supplies caller-owned ordered
writes, queue backpressure, socket lifecycle and mux-to-Port orchestration. Tests cover
multi-stream isolation, close races, ID/capacity/chunk bounds, peer violations,
completion/cancellation, redaction and fuzzing; no live interoperability claimed.

Native codec, protocol, and WebSocket fuzz targets pass. Synthetic streaming
tests cover bidirectional output/input, owned EOF, transport interruption, reader
joining, and canceled producers under backpressure. Both Linux architecture
package builds pass with CGO disabled; native-shell executable integration exists.
Dependency vulnerability scanning uses private temporary govulncheck v1.8.0
rebuilt with Go 1.27.2; the rescan reports no vulnerabilities. The user-installed
Go 1.26.9 scanner cannot load this Go 1.27 module and is not overwritten.
docs/development.md records current validation status and limits.

Directory:

    internal/transport/native/

Security classification: CRITICAL

Purpose:

Implements native Go communication with the AWS Session Manager
data channel.

### websocket.go

Secure WebSocket establishment and connection management.

### handshake.go

Session Manager handshake and initialization.

### message.go

Message structures, encoding, and decoding.

### protocol.go

Protocol message validation and dispatch.

### port.go

Implemented explicit-destination Port protocol/ConnectForward setup and validated
agent/property/control handling; no local listeners or tunnel workers.
`port_test.go` covers target validation and private expectation copies, strict
capability versions, exact/ambiguous/unsafe properties, terminal/control isolation,
sequence deduplication and parser fuzzing. Real TLS/HTTP synthetic agent tests
exercise SigV4/token setup, matching version advertisements, binary/control
delivery, owned-close EOF, caller cleanup and refusal of terminated sessions for
both instance-local and remote-host destinations. No live agent/tunnel proof.

### forward.go

Implemented owned loopback-listener/mux/socket worker orchestration through
ServeForward. Listener creation and AWS/CLI forwarding lifecycle are not provided.
`forward_test.go` verifies concurrent byte-isolated streams, non-reused retired
IDs, large/batched transfer backpressure, capacity/blocked-send/blocked-local-write
cancellation, full close after delivery, control/protocol/IO failures, cleanup
errors and loopback/capability/ownership gating. A real native-channel fixture
composes outer framing, acknowledgements and active-stream retransmission
deduplication with mux/socket serving. Tests use net.Pipe and synthetic listeners,
not OS TCP binds, live AWS, or an installed agent/smux implementation.

### control_json.go

Implemented private JSON structural validator used before decoding handshake
requests/actions/completions, acknowledgements, owned channel closure and local
resize input. Requires UTF-8 and one root object; rejects duplicate decoded keys
including case-fold aliases at every nesting level. Bounds control input to
64 KiB, containers to depth 16, objects to 64 keys and decoded keys to 256 bytes;
existing smaller per-message limits remain. Unknown unique fields remain allowed.
Errors never include input or parser causes. `control_json_test.go` covers bounds,
escaped/case duplicate keys, KMS/type confusion, acknowledgement identity, close
ownership/error ambiguity, permanent remote-protocol failure and fuzz parsing.
Ordinary NewProtocol still refuses Port without the explicit-destination path.

### mux.go

Implemented package-private inner smux v1 encoding/incremental parsing for future
native forwarding. Session creation is in ssm.StartForward and loopback creation
is in internal/forward/listener.go; CLI connect.go composes them with serving.

### mux_state.go

Implemented private client stream ownership/data/FIN state over the inner codec.
This state itself owns no network workers or local sockets; forward.go composes it
with the outer channel and owned socket workers.

### sequence.go

Message sequencing, acknowledgements, and ordering.

### stream.go

Bidirectional session data streaming.

### trace.go

Implemented opt-in bounded fixed-state observer through `WithTrace`/`Trace.Drain`.
Records only static labels and nonnegative time since creation, no remote/auth
objects or I/O. Channel records validated readiness and ownership end states;
CLI attaches only for debug, drains at stages and reports overflow. Trace mutex
protects concurrent drains without changing event-loop protocol decisions.
`trace_test.go` covers labels, bounds, context control and concurrent recording;
existing real TLS/shell/stream tests check readiness, failure and cancellation
state accuracy without payload leakage. `cli/native_diagnostics_test.go` tests
opt-in gating and real Connect failure with fresh owned AWS cleanup.

Responsibilities:

- Establish authenticated WebSocket connections.
- Process Session Manager messages.
- Validate framing and payload sizes.
- Handle sequencing and acknowledgements.
- Support interactive sessions.
- Support terminal resize behavior.
- Handle disconnections safely.

Security requirements:

- TLS verification is mandatory.
- Protocol input is untrusted.
- Message sizes must be bounded.
- Malformed input must not cause crashes.
- Connection retries must be bounded.
- Authentication material must never be logged.
- Avoid replaying sensitive messages unexpectedly.

Do not invent undocumented protocol behavior.

Use verified AWS implementations and documentation as references.

Native port forwarding may require additional files when
its implementation is introduced.

---

## 13. Session Manager Plugin Backend

Current files: `plugin.go`/`plugin_test.go` implement/test executable preflight;
`handoff.go`/`handoff_test.go` add the private owned-response environment boundary.
`Inspect` resolves trusted absolute PATH discovery, rejects unsafe file
modes, then performs a structured three-second/caller-deadline version probe with
no inherited environment/input. Fixed 64-byte stdout capture, discarded stderr,
canonical numeric parsing and the reviewed minimum 1.2.764.0 fail closed; errors
and formatted handles expose no child output/path. The direct child is reaped;
250ms WaitDelay bounds inherited-pipe draining, not malicious descendants.
Tests exercise real synthetic subprocesses, environment isolation, missing/relative
paths, malformed/oversized output, failed exits and cancellation, with parser fuzz
coverage. Executable provenance/parent directories and inspection-to-launch races
remain trusted/unchecked. `docs/plugin-backend.md` records official references and
pending token/identity/terminal/logging/forwarding gates. No session launch, CLI
selection or automatic fallback is enabled; `process.go` remains planned.
The guide also records reviewed upstream launch constraints: installation-wide
reloadable logging (including stream-URL reconnect errors), mixed raw startup
diagnostics/remote stdout, independent credential loads, background-context
resume/termination and replacement resume URLs. These are upstream source-review
findings, not controls implemented here or guarantees for installed versions.
The re-check pins mainline commit 7cde6748cc6cffbc69546b4de08e603cd39be6d8. Its new
initial URL validator is broader than the native exact regional TLS-only
boundary (including ws/extra-host overrides); the resume handler replaces the URL
without invoking that validator. It resolves neither Linux reloadable
logging nor selected-provider/child-output gates. No executable installation,
launch, relaxed endpoint policy or automatic fallback is introduced.

`prepareHandoff` accepts only live owned Session material, serializes the three
official response fields and rejects invalid UTF-8 or JSON-expanded entries above
120 KiB. A private redacted object supplies one named entry only to an explicit
child environment, strips all old response-prefix aliases and bounds entry count,
per-entry size and retained bytes (256/120 KiB/256 KiB). It never mutates global
environment, stores disk payloads or retrieves credentials. Clearing releases its
reference without claiming memory/copy erasure; termination prevents new preparation
but cannot revoke already copied material. Synthetic subprocess tests verify
the official lookup/unset/SDK decode convention, byte preservation, no argv response,
redaction, ownership/release refusal and limits. Full launch identity refresh,
environment/argument budget, lifetime coordination and official interoperability
remain pending; no operational plugin backend is claimed.

`credentials.go`/`credentials_test.go` add the private selected-provider response
adapter. It calls the same SDK provider/cache for each request, never resolves a
new chain, discards raw failures/partial results and checks cancellation before
and after retrieval. The official endpoint JSON carries only key/secret/token
and optional unchanged UTC expiration; bounded printable-ASCII fields, expired
credentials and oversized encoding fail closed. No credentials enter environment,
argv, disk or diagnostics here. Tests compose the real SDK endpoint provider's
GET/authorization/JSON decode with a synthetic HTTP boundary and parent SDK cache
invalidation, verify static/refreshable wire fields, error redaction, cancellation
and invalid metadata. The adapter itself opens no endpoint; child provider-chain
isolation during actual plugin execution and process integration remain pending.

`credential_server.go`/`credential_server_test.go` add a package-private authenticated
HTTP relay on dynamically assigned TCP4 127.0.0.1. It generates a random 256-bit
authorization value, accepts only exact origin-form GET/authority/path requests
with one matching Authorization and no body/query, and never reloads credentials.
At most eight accepted sockets and two concurrent selected-provider retrievals;
HTTP header/read/write timeouts, configured header bounds, no keepalives, fixed
uncached error responses and discarded HTTP diagnostics limit exposure. Retrieval
has a five-second request context. Cancellation closes sockets and joins admitted
handlers; timed-out shutdown reports incomplete work. SDK cache refresh internals
can outlive canceled retrieval and are not claimed joined. Only future explicit
launch integration may start it; no CLI/native behavior or AWS resources change.
Its two child endpoint/authentication settings are not a complete isolated child
environment. Handle formatting redacts them; close releases references and clears
the owned response buffer without claiming erasure of Go/HTTP/environment copies.
Offline tests cover rejection-before-provider, SDK decode/refresh, error redaction,
SDK cache cancellation limits, retrieval/socket capacity and once-only cleanup.
Connection-close failures are retained as fixed shutdown errors, never raw causes.
Opt-in OS socket/race tests verify authenticated/unauthenticated requests, parent
cancellation, idempotent close and explicitly incomplete shutdown with a context-
ignoring provider. They use synthetic data, not live AWS or an official plugin.

`environment.go`/`environment_test.go` add a private explicit child-environment
builder. It uses only selected region, live relay settings and an allowlist of
explicit noncredential PATH/terminal/locale/proxy/CA settings. Credentials,
profiles, web identity, ECS relative URI/auth files, endpoint overrides, loader
variables and plugin configure bypass are rejected. Both SDK shared-file paths
are /dev/null, IMDS is disabled, defaults/retries are fixed and environment values
are never diagnostics. PATH and CA file/directory entries must be absolute;
settings/entry/value bounds, duplicate rejection, redacted formatting, copy
ownership, refusal after relay stop and reference clearing are tested. Clean
subprocesses resolve the
actual SDK endpoint chain and invalidate the child cache for two selected-provider
retrievals and prove an endpoint failure returns no fallback credentials.
Offline tests configure the endpoint provider's separate HTTP client;
opt-in OS tests use its ordinary client with proxy settings unchanged. No native/
CLI launch changes. Resolved parent network/CA fidelity, empty profile argument,
owned-response assembly and installed-plugin behavior remain integration gates.
The reviewed Linux plugin uses stty through PATH for terminal settings/restoration;
that external helper and trusted discovery must be checked before launch, not
assumed from the version probe.

`logging_linux.go`/`logging_linux_test.go` implement a private read-only logging
preflight for the fixed /usr/local/sessionmanagerplugin/seelog.xml path. Ancestor
directories and the regular config must be root-owned with no group/world writes
or symlinks/set-ID modes. A NOFOLLOW/nonblocking open, matching before/after file
identity and bounded 1025-byte read refuse substitutions, special files and input
above 1024 bytes. The narrow XML policy accepts only a seelog root with type=sync,
minlevel=off and whitespace, with no exceptions/outputs/extra attributes or XML
metadata. All failures omit configuration contents and OS causes. The pinned
vendored parser supports this grammar; default off logging still has a test-file
exception and file outputs. Tests cover grammar/bounds/read errors, synthetic
ownership/mode policies, real local symlink/non-root refusal and cancellation;
they do not exercise an installed plugin or its reload behavior. Root admins
remain trusted to preserve settings during the child lifetime; preflight is not
a lock, sandbox or full launch authorization. No configuration is changed and
the future launcher has not yet integrated this check.

Directory:

    internal/transport/plugin/

Security classification: CRITICAL (credential/session-token handoff and trusted subprocesses)

Purpose:

Provides compatibility with the official AWS Session Manager
Plugin when native functionality is unavailable.

### plugin.go

Implemented plugin discovery and bounded version preflight. Invocation of a
session remains planned.

### process.go

Child-process execution and lifecycle handling.

### handoff.go

Implemented private owned session-response encoding and explicit child-environment
assembly; authentication material is never a command argument or diagnostic.

### credentials.go

Implemented private selected-SDK-provider retrieval and endpoint-compatible JSON
encoding. Returned bytes are secret-bearing transport data, not diagnostics;
the relay below supplies authenticated local transport; plugin integration remains
planned.

### credential_server.go

Implemented private authenticated loopback credential relay and bounded HTTP/
retrieval/socket lifecycle. It is not called by CLI; it does not isolate the
child's provider chain, constrain plugin logs/reconnects or launch a process.

### environment.go

Implemented explicit private child identity/settings environment builder. It
returns copied secret-bearing entries only at the process boundary; it is not a
launcher or a guarantee that an installed child obeys the selected provider.

### logging_linux.go

Implemented private fixed-path protected-file/disabled-XML logging preflight.
It is read-only and not yet invoked by CLI or a session launcher; trusted root
changes and installed-binary logger semantics remain outside this check.

Requirements:

- Detect the plugin executable.
- Use structured process arguments.
- Never execute through a local shell.
- Avoid leaking tokens through logs.
- Preserve terminal interaction.
- Handle child-process termination.
- Report missing dependencies clearly.

Important:

This backend requires an external runtime executable.

The project must not claim complete standalone operation
when this backend is required.

Do not download or install the plugin automatically.

---

## 14. Terminal Package

`mfa_linux.go` implements controlling-terminal MFA input using canonical/no-echo
settings, bounded reads and six-digit validation, private descriptors and full
restoration. It clears input queues before/after reading to prevent pasted codes
from becoming later remote input; failures discard the returned code. It never
logs/persists input. CLI prompting ends permanently before remote terminal Run;
MFA refresh after establishment (including cleanup) fails closed when needed.
`mfa_linux_test.go` verifies canonical no-echo reading, malformed/oversized code
rejection, queue clearing, complete restoration and cancellation using real PTYs.
Subprocesses verify actual controlling-terminal input versus redirected stdin,
absence of a controlling terminal, and keyboard Ctrl+C. `cli/mfa_test.go` covers
fresh-code callbacks, setup cancellation, in-flight close serialization, and
disabling prompts before remote terminal Run.

Implemented: `terminal_linux.go`, `io_linux.go`, `escape.go`, `session_linux.go`,
`terminal_linux_test.go`, `escape_test.go`, and `session_linux_test.go`. Other file
names below remain planned; session orchestration is in `session_linux.go`. Raw-mode
control has an ioctl test boundary and restores the full configuration, not just
selected flags. Physical Ctrl+C/Ctrl+D become remote input bytes in raw mode.
Unexpected ioctl errors are reported, not classified as non-TTY. Streams reject
non-terminal character devices and socket inputs, never create files, and report
close failures. Their owner must stop/join I/O users before closing descriptors.
Pipe/TTY cancellation is polled every 100ms; regular filesystem calls may block.
`session_linux.go` owns shell I/O orchestration and channel shutdown; `Run`
registers SIGWINCH and external SIGINT/SIGTERM/SIGHUP/SIGQUIT cancellation.
Input EOF sends a single remote Ctrl+D and keeps draining output. Local escapes
apply only to TTY input; native chunks are bounded even when escape processing
adds a pending tilde. Workers are joined before terminal/descriptor cleanup;
independent errors racing with cancellation are preserved. Native Close's exact
context-canceled leaves are removed without hiding joined cleanup failures.
SSM TerminateSession remains caller-owned. No terminal streams are logged.

Directory:

    internal/terminal/

Security classification: HIGH

Purpose:

Provides correct Linux terminal behavior.

### terminal.go

Terminal session orchestration.

### rawmode.go

TTY raw-mode activation and restoration.

### resize.go

SIGWINCH and terminal dimension handling.

### signals.go

Signal management.

### escape.go

Client escape-sequence processing.

Responsibilities:

- Manage stdin/stdout.
- Handle raw terminal mode.
- Restore terminal state.
- Handle window resizing.
- Support interactive terminal applications.
- Handle local disconnect sequences.
- Distinguish local and remote interrupt behavior.

Security requirements:

- Do not log terminal input.
- Do not capture passwords.
- Do not retain unnecessary terminal buffers.
- Restore terminal settings on controllable exits.
- Avoid terminal-state corruption.

Use established Go terminal libraries where appropriate.

---

## 15. Remote Command Package

Implemented: `execute.go`, `exitcode.go`, `quote.go`, and their colocated tests.
CLI command execution uses these with document preflight and owned cleanup.
The Channel boundary requires native authenticated sequencing and owned-close
validation. Result.ExitCode reports availability explicitly; ordinary stdout
never supplies status. Duplicate/malformed/unavailable status, output after
status, disconnect, cancellation, local output or cleanup failures invalidate
the result. Only exact shutdown-cancellation leaves are filtered from Close.
No stdin/raw mode/resize/local execution occurs. AWS session cleanup stays with
the caller. Regular-file writes retain terminal Stream's kernel-I/O limitation.

Directory:

    internal/command/

Security classification: HIGH

Purpose:

Executes requested remote commands through supported SSM
session mechanisms.

### execute.go

Implemented result receiver for established noninteractive channels. Owns local
stdout/stderr descriptors and channel Close, not StartSession/TerminateSession.
CLI connect.go supplies execution orchestration and AWS ownership.

### quote.go

Implemented bounded POSIX serialization of one remote /bin/sh -c argument.

### exitcode.go

Implemented bounded parser for typed canonical AWS ASCII exit-status payloads.

Responsibilities:

- Pass remote command requests safely.
- Avoid local shell execution.
- Preserve intended remote command semantics.
- Handle noninteractive sessions.
- Propagate reliable exit statuses where supported.

Security requirements:

- Never execute remote command text locally.
- Never silently invoke sudo.
- Never substitute SSM Run Command implicitly.
- Never report fabricated exit codes.
- Document shell interpretation rules.

---

## 16. Port Forwarding Package

The separate native package now has a Port channel, inner smux v1 codec/client
state and owned-listener/socket serving orchestration. This package now implements
listener creation in listener.go, with listener_test.go; CLI connect.go now
composes the lifecycle and ssm.StartForward supplies fixed-document session
creation. Synthetic tests do not prove OS TCP binding or a
live AWS tunnel; the optional OS test requires SSMH_TEST_TCP=1.

Directory:

    internal/forward/

Security classification: CRITICAL

Purpose:

Manages SSM TCP port forwarding.

### forward.go

Planned port-forwarding orchestration; listener.go is this package's only source
implementation so far.

### listener.go

Implemented Listen creates only tcp4 127.0.0.1 at the exact validated local port,
using net.ListenConfig and the caller's setup context. No remote DNS resolution,
alternate port, public/IPv6 bind, privilege escalation or accept occurs here.
Successful return transfers ownership to the caller; later setup cancellation
does not close a returned listener. The caller must close on setup failure or
transfer it to native ServeForward. Partial/error, post-bind cancellation and
unexpected-address results are closed with cleanup failures retained. Error
messages distinguish conflicts/permission failures without retaining raw network
causes. No AWS calls or session ownership. Tests cover validation, exact binding
arguments, ownership, cancellation, partial returns, address gates and redaction;
real OS binding/conflict/accept is explicitly opt-in. The test now passes after
user-enabled network access; it does not prove a live AWS tunnel.

### target.go

Remote destination representation.

### validate.go

Port and host validation.

Supported planned modes:

- Local port to EC2 instance port.
- Local port to a remote host reachable from the instance.

Security requirements:

- Bind to 127.0.0.1 by default.
- Do not expose listeners publicly.
- Validate ports.
- Validate destination hostnames.
- Avoid privileged operations.
- Do not alter firewall rules.
- Do not log TCP payloads.
- Clean up listeners on termination.

Actual tunnel transport belongs to the selected SSM
transport backend.

Do not implement a TCP tunnel by treating an interactive shell
data stream as a raw socket.

---

## 17. Logging Package

Current files: `errors.go` and `errors_test.go`. `Failure` exposes allowlisted
messages without retaining raw SDK/credential-provider causes; `SafeText` removes
terminal controls and Unicode format controls from diagnostic metadata. Logger
configuration and detailed protocol diagnostics below are still planned.
The CLI's `diagnostics.go` currently owns allowlisted lifecycle-stage reporting
and validated identity presentation using private cancellable terminal Streams;
debug SDK operation summaries are collected by `aws/metrics.go` and drained by
the CLI without exposing raw SDK data or interfering with AWS ownership tracking.

Directory:

    internal/logging/

Security classification: CRITICAL

Purpose:

Provides consistent, safe application diagnostics.

### logger.go

Logging configuration and output.

### redact.go

Sensitive-data redaction helpers.

Responsibilities:

- Support normal, verbose, and debug modes.
- Send diagnostics to stderr.
- Protect stdout for command and JSON output.
- Redact sensitive fields.
- Avoid secret-bearing object dumps.

Never log:

- AWS secrets.
- Session tokens.
- MFA codes.
- Authorization headers.
- Complete authenticated WebSocket URLs.
- Interactive terminal input.
- Forwarded TCP data.

Prefer explicitly selected diagnostic fields over generic
serialization.

---

## 18. Version Package

Implemented: `version.go` provides a linker-injected Version (default `dev`) and
sanitized CLI formatting with Go runtime and platform. No Git or build timestamp
is required; no filesystem paths are included.

Directory:

    internal/version/

Purpose:

Provides build and version metadata.

### version.go

Stores version information supplied through Go linker flags.

Potential fields:

- Version.
- Commit identifier, when Git becomes available.
- Build date, if desired.
- Go runtime version.

Do not assume Git metadata exists.

The application must build correctly before Git is initialized.

---

## 19. Tests

Directory:

    tests/

Purpose:

Contains cross-package integration tests and supporting fixtures.

Unit tests SHOULD generally reside next to their corresponding
Go implementation files.

Examples:

    internal/aws/assume_role_test.go
    internal/ec2/resolver_test.go
    internal/ssm/lifecycle_test.go
    internal/transport/native/message_test.go
    internal/forward/validate_test.go

### tests/integration/

Implemented Linux-only optional native AWS tests in `native_test.go`, with offline
guard/collector tests in `guard_test.go`. SSMH_TEST_AWS selects exactly one check,
shell, shell-tty, command, forward or forward-host operation; explicit ID, region and expected
account are required before authentication. One selected SDK config is retained
through STS account guard, complete EC2 running/SSM Linux Online checks, session
creation and native transport. Check never starts a session. Shell sends a split
nonce printf/exit through redirected input; command requires an approved separate-
output document and asserts distinct streams plus typed exit 37. Forwarding uses
an explicitly approved nonprivileged loopback port and pre-existing echo service,
checking three simultaneous byte-isolated streams. No instance/service/document
creation or privileged remote commands; opting in can incur existing logging/data
costs. Session/control cleanup uses only owned IDs with a fresh ten-second budget
after channel/socket shutdown; failures are reported, not claimed away.

Redirected capture is private in-memory pipe I/O capped at 1 MiB per output stream, with
joined readers and overflow cancellation. No transcripts, secrets or raw failures
are printed or written to disk. The 30-second setup budget and 90-second whole-test
context are bounded separately from cleanup; forwarding first reserves its port
with a five-second budget. Offline tests verify opt-in/validation, stream isolation,
EOF, capture limits, cancellation and independent-error preservation without AWS.
Synthetic STS tests require a matching validated account and reject malformed,
denied/expired/failed identity and pre-cancellation without metadata fallback.
`tty_linux_test.go` adds a separately opted-in shell-tty operation. A private
nonblocking master PTY is opened before AWS authentication, not the developer's
terminal; the same selected SDK config/account guard owns StartSession and cleanup.
The production terminal runner is checked for raw state, initial remote stty size,
resized dimensions after real SIGWINCH, Ctrl+C interrupting a bounded remote child
sleep without closing the client, Ctrl+D completion and complete local termios
restoration after joined workers. Probe markers are split in remote printf arguments
so echo cannot satisfy output assertions. At most ten probes per size stage and
ten-second phase deadlines bound work; per-probe in-memory capture is capped at
1 MiB without transcript/error disclosure. Remote prerequisites include stty, sh,
printf and sleep; no installation or privileged command is attempted. Offline
real-PTY tests exercise the harness with a synthetic channel, physical control
bytes, SIGWINCH, bounded/redacted collection and restoration, not live AWS proof.
The production library/native/terminal path is covered, not the complete CLI
process, external termination signals, full-screen apps or ARM64 runtime.
Live cases remain unexecuted/unverified pending approved
credentials/target/test scope; default runs skip before credential resolution.

### tests/documentation/

Implemented offline policy-example validation in `iam_policy_test.go`: JSON
structure and exact action/resource/condition scope, no IAM simulation or AWS calls.
`authentication_test.go` validates the guide's SSO configuration with the actual
SDK shared-config loader and client examples with the CLI parser. It never runs
shell examples or resolves credentials.
`acceptance_test.go` compares the audit inventory with numbered PROMPT sections,
acceptance criteria and actual CLI flag registrations. It guards omissions only;
it does not validate row assessments, evidence sufficiency or live functionality.
`links_test.go` verifies simple inline repository file links in README and every
docs guide resolve to existing regular files inside the repository. It does not
validate heading anchors, arbitrary CommonMark constructs or external websites.

### tests/build/

Implemented Linux-only `release_test.go`: exact `SSMH_TEST_BUILD=1` opt-in,
two source-only temporary copies without Git/credentials/tests, actual Makefile
AMD64/ARM64 release builds and SHA-256 equality across source locations. Inspect
ELF class/machine, absence of dynamic interpreter/linking/debug/symbol sections,
static/trimpath build settings, embedded version marker, absence of VCS/source-root metadata and the native
architecture's `--version`. Also invokes plain `go build` in one isolated root,
checks the default dev version and compares root/cmd compiled help byte-for-byte.
Root build uses CGO=0 but does not claim Makefile release stripping/trimpath.
Child environment allowlists tool/cache locations,
disables Go user/workspace/execution overrides and module downloads, and uses
the test's exact Go toolchain. Gate/environment tests run offline by default;
four release builds plus one root build require `make verify-release`, cached
dependencies and make. Five-
minute execution budget cancels the spawned build process group; bounded native
version-probe pipe draining applies. Outputs are
temporary and no workspace artifacts or AWS resources are changed. This tests
same-toolchain/input reproducibility, not cross-toolchain or foreign-architecture
runtime behavior, live interoperability or release provenance.
An opted-in Go 1.27.2 run passed byte-identical, stripped static ELF builds for
both architectures and the AMD64 version probe; ARM64 runtime remains untested.

### tests/fixtures/

Contains synthetic test data.

Never include:

- Real AWS credentials.
- Real session tokens.
- Sensitive customer data.
- Private keys.
- Real authentication payloads.

Protocol fixtures must be based on verified behavior.

---

## 20. Documentation Directory

Directory:

    docs/

### acceptance.md

Implemented requirement/evidence map for every PROMPT section, all named CLI
options and all 18 numbered acceptance criteria. Separates local implementation/
synthetic/build evidence from incomplete plugin integration and missing live
shell/profile/role/discovery/TTY/forwarding/cleanup proof. Links current sources
and tests, records supported limits/optional UI, and identifies approved-target
authorization and implementation gates without narrowing the original scope.
It is an audit aid, not live validation or a completion declaration; update
affected rows when evidence or implementation changes.

### architecture.md

Implemented current-source architecture and ownership guide: shared CLI lifecycle,
selected SDK authentication, operation-specific document/capability boundaries,
channel/local/AWS cleanup ordering, guarded CA/proxy handling and diagnostic
separation. Identifies unfinished plugin, KMS forwarding support and missing
live/ARM64-runtime verification; no planned package is presented as operational.

### discovery.md

Implemented documentation of the EC2 discovery/resolver and SSM inventory prerequisites, verified AWS
filter/pagination references, local bounds, no-partial-result semantics and
implemented read-only CLI listing/check/JSON and connection Name/state validation.
It distinguishes inventory reports from authorization/readiness proof.

### diagnostics.md

Implemented verbose/debug identity and fixed lifecycle reporting, stage-duration
semantics, bounded private diagnostic descriptors, redaction and cleanup behavior.
Includes verified STS/SDK references, debug-only operation/attempt semantics,
bounded buffering, fixed native state/timestamp reporting, safe numeric provider-source classification and remaining
protocol gaps.

### security.md

Status: IMPLEMENTED (current threat model; no certification or live security audit)

Trust-boundary/deployment guide verified against implemented CLI, SDK, session,
document, native and terminal behavior. Describes trusted local credential
programs/configuration, SDK cache writes, in-memory secret limitations, TLS versus
document-owned KMS shell/command encryption and forwarding limits, bounded protocol processing, SDK response-decoding
and filesystem cancellation limits, document-version race, remote OS privilege
and raw terminal-output risks. Distinguishes local diagnostics from AWS/target
logging and shell versus SSH/forwarding audit visibility with official references.
Documents process-owned best-effort cleanup and outstanding release gates;
README links to it. It does not claim forwarding, discovery or plugin completion.

### authentication.md

Implemented guide to SDK profile/region selection, synthetic modern SSO configuration,
separate login prerequisites, explicit AssumeRole, secure MFA and refresh/cleanup
limits. Describes SDK-owned SSO cache writes and preserved existing permissions,
trusted credential-process configuration, redacted diagnostics and current
endpoint restrictions, custom-CA precedence and trust semantics. No live
authentication validation is asserted.

### iam-policy.md

Status: IMPLEMENTED (guide and offline scope tests; live policy validation pending)

Current caller permission map, narrow single-instance IAM-user shell example,
source AssumeRole example, scoped cleanup/system-tag caveats for federated roles,
agent/network prerequisites, and planned-feature permission distinctions. Records
the official OpenDataChannel resource-scoping documentation conflict; no broad
grant or successful live authorization is claimed. README links to this guide.

### native-protocol.md

Status: IMPLEMENTED (current codec and reference documentation; full transport
specification remains in progress).

Includes the pinned agent/plugin KMS source comparison, random-context and
directional-key/challenge implementation prerequisites, fixed actionable
refusal regression scope and private payload-codec/protocol bounds/lifetime/test evidence.
Native KMS shell/command integration has synthetic TLS/SDK coverage, not live proof.

Verified Session Manager protocol behavior and references.

Should distinguish confirmed behavior from implementation
assumptions or unresolved questions.

### plugin-backend.md

Implemented guide to executable discovery/version preflight, response-handoff
preparation and the local-code trust boundary. Documents child environment
isolation/assembly bounds, response/copy lifecycle and redaction, verified AWS
version/handoff references and incomplete backend launch/security gates.
Also documents the selected-provider response adapter, private authenticated
loopback relay, bounded socket/handler lifecycle, SDK cancellation limits and real
SDK decoder/cache tests without claiming installed-plugin refresh integration.
Describes the explicit child environment, profile/metadata isolation, trusted
stty dependency, resolved CA/proxy transfer gate and actual SDK subprocess checks.
Records upstream logging/output/credential/reconnect findings and the resulting
launch gates; stripped environment and a version probe are not log suppression
or selected-identity guarantees. Documents the private protected-config logging
preflight, its narrow disabled grammar, default exceptions/file effects and
trusted-admin/reload/syscall limits. No installed plugin/live behavior is asserted.
Records the reviewed snapshot's missing random-context KMS acknowledgement against
the pinned agent requirement; minimum version alone does not establish compatibility.
Does not describe an operational compatibility or forwarding backend.

### native-forwarding.md

Implemented AWS Port/smux transport-layer references and the private inner
codec/state bounds, failure/ownership semantics and offline test scope. Clearly marks
live interoperability as unverified and records the passing opt-in OS listener
test; CLI lifecycle integration is now
implemented. Documents implemented ServeForward ownership,
queue/deadline bounds, full-close semantics, shutdown and synthetic test scope.

### troubleshooting.md

Implemented safe stage-oriented troubleshooting for option/backend refusal,
port conflicts, credentials/SSO/MFA/role failures, complete Online validation,
IAM/documents, CA/proxy/TLS/channel errors, forwarding semantics and cleanup.
No raw secret dumps, insecure TLS, privilege/identity substitution, unsolicited
permission-test sessions or automatic infrastructure changes are suggested.

### development.md

Implemented actual Makefile/toolchain/test/build workflow, target artifacts,
offline-cache limits, synthetic versus opted-in OS/live verification, scanner
absence, fuzz/race scope, security/CODEX review and remaining release gates.
Documents only exact generated-file cleanup; no automatic commits/publishing.

Do not create empty documentation files simply to match the
proposed structure.

---

## 21. Component Dependency Direction

Both root and cmd executable wrappers delegate to internal/app, which invokes
CLI and owns only process signals, final reporting and exit-code mapping.
The intended high-level dependency flow below begins at CLI:

    CLI
     |
     v
    Configuration
     |
     v
    AWS Authentication
     |
     +--------------------+
     |                    |
     v                    v
    EC2 Discovery       SSM API
                          |
                          v
                     Session Lifecycle
                          |
                          v
                       Transport
                       /       \
                      /         \
                   Native       Plugin
                      \         /
                       \       /
                        v     v
                       Terminal
                          |
                          v
                         User

Remote command execution and forwarding are operation-specific
orchestration layers that use the SSM and transport components.

Logging and version metadata are shared support components.

Avoid circular package dependencies.

The implemented terminal package imports native message types through its
`Channel` interface; native transport does not import terminal. The CLI
composes AWS control/session ownership, native Connect, and terminal Run or
command.Run. The command package imports native message types and terminal
Stream primitives; native transport does not import command. Command serialization
is performed before authentication; authenticated document preflight precedes
StartSession. Command.Run owns channel shutdown, while CLI connect.go retains
AWS session ownership and cleanup.
Terminal Run owns channel shutdown but never acquires AWS session ownership or
performs TerminateSession itself.
Native ServeForward similarly owns only an established Port channel, a supplied
matching loopback listener and its accepted connections. Its private test boundary
sits below Port authentication. Native code imports validated configuration DTOs
for immutable forwarding expectations, never CLI parsing or terminal code; AWS
StartSession/TerminateSession remain orchestration concerns. internal/forward
imports only configuration DTOs and the standard library for Listen; it does not
import native transport or perform AWS operations.

Do not allow lower-level transport packages to depend on CLI
argument parsing.

Authentication should be centralized, not duplicated across
multiple components.

---

## 22. Security Boundaries

The following components require particular scrutiny.

| Component | Classification | Primary Security Responsibility |
|---|---|---|
| AWS authentication | CRITICAL | Credential resolution and protection |
| STS AssumeRole | CRITICAL | Explicit identity transition |
| EC2 discovery | HIGH | Correct target identification |
| SSM API | CRITICAL | Authorized session creation and ownership |
| Native transport | CRITICAL | Authenticated protocol communication |
| Plugin backend | CRITICAL | Credential/session-token handoff and safe subprocess execution |
| Terminal | HIGH | Safe interactive input and terminal state |
| Remote commands | HIGH | Command handling and injection prevention |
| Port forwarding | CRITICAL | Local network exposure |
| Logging | CRITICAL | Sensitive-data protection |
| CLI | HIGH | Input validation and safe behavior |
| Build/release | HIGH | Dependency and artifact integrity |

When a CRITICAL component changes, the agent MUST perform an
explicit security review of the relevant behavior.

Security reviews should include applicable adjacent components.

For example:

Changing AssumeRole behavior may affect:

- AWS client construction.
- Session authorization.
- Instance discovery.
- Session creation.
- Diagnostic identity output.

Changing native transport may affect:

- Protocol validation.
- Session lifecycle.
- Terminal behavior.
- Reconnection handling.
- Port forwarding.

---

## 23. Key Application Workflows

### Interactive Connection

    User invokes ssmh
           |
           v
    Parse and validate arguments
           |
           v
    Resolve AWS credentials
           |
           v
    Assume IAM role if requested
           |
           v
    Resolve AWS region
           |
           v
    Resolve EC2 instance
           |
           v
    Check SSM availability
           |
           v
    Start SSM session
           |
           v
    Establish transport backend
           |
           v
    Initialize terminal
           |
           v
    Exchange interactive data
           |
           v
    Disconnect and restore terminal
           |
           v
    Terminate owned SSM session

### Port Forwarding

    CLI
     |
     v
    Validate forwarding parameters
     |
     v
    Authenticate with AWS
     |
     v
    Resolve target instance
     |
     v
    Start forwarding session
     |
     v
    Establish supported forwarding transport
     |
     v
    Bind local loopback listener
     |
     v
    Forward traffic
     |
     v
    Close listener and session

Actual ordering of some setup operations may vary when needed
for correctness, but security invariants must remain intact.

---

## 24. Architectural Decisions

### ADR-001: Go Implementation

Status: ACCEPTED

The application is implemented in Go.

Rationale:

- Native Linux binaries.
- Strong concurrency support.
- AWS SDK v2 availability.
- Good standard library.
- Straightforward deployment.

### ADR-002: AWS SDK v2

Status: ACCEPTED

Use AWS SDK for Go v2.

Do not introduce AWS SDK v1.

### ADR-003: SSM Rather Than SSH

Status: ACCEPTED

Native SSM sessions are the intended connection mechanism.

Do not require an SSH daemon, SSH key, or port 22.

### ADR-004: Native Transport Preferred

Status: ACCEPTED

Prefer native Go Session Manager transport where correctly
implemented and validated.

The official Session Manager Plugin may be used as a documented
compatibility backend.

### ADR-005: Explicit AWS Identity

Status: ACCEPTED

An explicitly requested AssumeRole operation must either
succeed or fail.

Never silently switch back to the original identity.

### ADR-006: Loopback Port Forwarding

Status: ACCEPTED

Port forwarding binds to 127.0.0.1 by default.

Public listeners must never be implicit.

### ADR-007: No Git Assumption

Status: ACCEPTED

The repository may initially exist without `.git`.

Build and development workflows must work without Git metadata.

### ADR-008: CODEX.md Maintenance

Status: ACCEPTED

The repository map must be kept synchronized with source changes.

All agents are responsible for maintaining it.

---

## 25. Implementation Roadmap

### Phase 1 - Foundation

Status: IN PROGRESS

Components:

- Project initialization.
- CLI framework.
- Configuration validation.
- AWS SDK v2 integration.
- Credential resolution.
- Region resolution.
- AssumeRole.
- Initial documentation.

### Phase 2 - Interactive Sessions

Status: IN PROGRESS (SSM ownership, native channel, terminal and executable
integration implemented; live interoperability and full readiness validation pending)

Components:

- SSM StartSession.
- SSM TerminateSession.
- Session ownership.
- Functional transport backend.
- Terminal raw mode.
- Terminal resizing.
- Signal handling.
- Safe cleanup.

Priority: HIGHEST

A working interactive shell is the first major milestone.

### Phase 3 - Discovery and Diagnostics

Status: IN PROGRESS (bounded read-only EC2 discovery/Name resolver and SSM inventory
and read-only list/check/JSON and connection Name/state validation implemented;
live verification pending)

Components:

- Instance discovery.
- Name tag resolution.
- SSM status checks.
- List output.
- JSON output.
- Connection diagnostics.

### Phase 4 - Remote Commands

Status: IN PROGRESS (CLI, quoting, document preflight and result handling
implemented; compatible document configuration and live verification required)

Components:

- Remote command execution.
- Command quoting.
- Remote exit-status handling.
- Noninteractive output.

### Phase 5 - Port Forwarding

Status: IN PROGRESS (inner smux codec, client stream state and explicit-destination
Port channel setup, fixed-document AWS session creation, loopback listener
creation, owned-listener/socket serving and CLI/AWS lifecycle integration
implemented; opt-in OS listener verified, live interoperability/release validation pending)

Components:

- Local port forwarding.
- Remote-host forwarding.
- Listener management.
- Forwarding protocol support.
- Security validation.

### Phase 6 - Hardening and Release

Status: PLANNED

Components:

- Security review.
- Protocol fuzz testing.
- Race detection.
- Dependency vulnerability checks.
- Documentation completion.
- Linux AMD64 builds.
- Linux ARM64 builds.
- Release packaging.

---

## 26. Development Commands

The Makefile implements these commands. `make security` requires an installed
govulncheck and fails if it is unavailable; scanning must not be claimed as passed.
Override GO when the default launcher is unusable. Release builds use CGO=0,
trimpath, disabled VCS stamping, stripped symbols, and explicit version metadata.

Build:

    make build

Tests:

    make test

Lint:

    make lint

Security checks:

    make security

Release:

    make release

Direct Go commands:

    gofmt -w .
    go vet ./...
    go test ./...
    go test -race ./...
    go mod verify

Optional vulnerability scanning:

    govulncheck ./...

Commands must not be described as passing until actually run.

---

## 27. Rules for Updating This Document

Codex MUST update CODEX.md when:

- A new file is added.
- An existing file is deleted or renamed.
- A package responsibility changes.
- An important interface changes.
- Dependencies between components change.
- A security boundary changes.
- A planned component becomes implemented.
- A component becomes deprecated.
- An architectural decision is made or revised.

### Update Procedure

1. Inspect the actual repository.
2. Compare existing files against the repository map.
3. Identify outdated descriptions.
4. Update the relevant sections.
5. Update component status.
6. Update security classifications if applicable.
7. Verify that referenced paths exist or are marked PLANNED.
8. Include the documentation update with the associated work.

Do not rewrite the entire document unnecessarily.

Do not remove useful architectural history without reason.

Do not represent planned files as implemented.

---

## 28. Final Repository Principle

`ssmh` must remain a small, understandable, security-focused
remote-access utility.

The architecture should make it easy to answer:

- Where are AWS credentials resolved?
- Where is IAM role assumption performed?
- Where is an EC2 instance selected?
- Where are SSM sessions created?
- Where are session tokens handled?
- Where is the WebSocket protocol implemented?
- Where are terminal settings managed?
- Where are local TCP listeners created?
- Where are sensitive values redacted?
- Where are session cleanup guarantees enforced?

Each question should have a clear architectural answer.

Avoid sprawling packages, duplicated responsibilities,
unnecessary frameworks, and hidden dependencies.

Security-sensitive code should be isolated, documented,
reviewable, and thoroughly tested.

The repository map must always describe the real project,
not an idealized or outdated version of it.

