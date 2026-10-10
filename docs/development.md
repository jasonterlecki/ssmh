# Development and verification

Read [AGENTS.md](../AGENTS.md) and [CODEX.md](../CODEX.md) before changes. The source
is authoritative; update CODEX with changed file responsibilities, interfaces,
security boundaries and implementation status in the same task. Do not initialize
Git, select a license or publish releases unless explicitly authorized. Source
commits and pushes are authorized and required after each completed logical
change by AGENTS.md Section 21: validate, synchronize CODEX.md, inspect and stage
only task-owned files, commit and normally push to the configured upstream.
Report blockers instead of forcing pushes or changing Git configuration. Existing
worktree changes belong to the user. The project is still a development client,
not a certified or live-validated release.

## Toolchain and builds

Use Linux with Go 1.27.2 or later. The module minimum includes the October 2026
[Go security fixes](https://go.dev/doc/devel/release#go1.27.2); an older toolchain
must upgrade through Go's supported selection or refuse the build. The module
name is `ssmh`, not an asserted remote
repository URL. Runtime binaries do not require Go or AWS CLI. Native operation
does not launch session-manager-plugin; its compatibility backend is unfinished.
Dependency versions/checksums are pinned in go.mod/go.sum; review security-sensitive
upgrades and run validation rather than blindly updating them.
The authentication dependency review selected config v1.32.19/credentials
v1.19.18 for SDK login-cache permission support, with their minimum required
STS/SSO/Signin/IMDS updates. This is a targeted patch, not an assertion that every
dependency is the newest available. The October 2026 version inventory also
contains larger SDK serialization/socket changes that require separate review.
See [cache security behavior](authentication.md); existing permissions are not
automatically repaired.

```sh
make build
make release VERSION=v0.1.0-dev
```

`build` writes `bin/ssmh`; `release` writes Linux AMD64 and ARM64 files in `dist/`.
Both use CGO=0, trimpath and disabled VCS stamping. Release additionally strips
symbols. Version is linker metadata, never an AWS wire-capability selector. These
targets compile but do not publish artifacts or prove target-architecture runtime
behavior. No source credential material belongs in binaries.

Plain `go build` at the repository root produces `./ssmh`; set CGO_ENABLED=0
for a CGO-free local binary. Root `main.go` and `cmd/ssmh/main.go` share
internal/app's process/signal/error/exit handling and the same CLI. The Makefile
remains the release path for trimpath, stripping and injected version metadata.

Verify the release recipe's same-toolchain reproducibility separately:

```sh
make verify-release
```

This opt-in test builds both architectures twice from separate temporary source-
only directories, using the actual Makefile and a fixed synthetic version. It
compares SHA-256 digests byte-for-byte, checks static stripped ELF architecture/build
settings and the version marker, rejects embedded source-root/VCS metadata and runs `--version` on the
host architecture. Dependencies must already be cached: module downloads, user
Go settings/workspaces and inherited AWS credentials are disabled for the child
builds. It uses the test's exact Go toolchain, does not change `bin/` or `dist/`,
and removes temporary copies through test cleanup. It additionally runs plain
root `go build` with CGO=0, checks its default dev version and compares root/cmd
compiled help. Ordinary tests skip the four release builds and one root build
unless `SSMH_TEST_BUILD=1`; gate/environment checks still run. It proves
same-input/toolchain builds across source locations, not cross-toolchain equality,
ARM64 execution on an AMD64 host, artifact provenance or live AWS behavior.
The opted-in Go 1.27.2 check passed for both architectures and the AMD64 version
probe. Rerun it after build/source/toolchain changes; that result is not a claim
that all future versions are reproducible.

Override GO if necessary. This development host's Snap launcher fails confinement,
while its native Go binary works:

```sh
make GO=/snap/go/current/bin/go build release
GOPROXY=off GOCACHE=/tmp/ssmh-go-build /snap/go/current/bin/go test ./...
```

These paths describe this host, not a portable installation requirement. Offline
mode requires every dependency and the selected Go toolchain in the module cache.
After the user enabled network
access, the normal EC2 SDK download succeeded; v1.304.0 is pinned to fit the current
SDK dependency set without unrelated upgrades. Earlier socket denials were a
sandbox restriction, not evidence of broken host DNS. Do not silently replace
SDK clients or bypass an environment's restrictions.

## Default verification

```sh
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go mod verify
```

Apply gofmt to changed Go files; its list should be empty afterwards. Make targets
`test`, `race` and `lint` invoke the corresponding checks. `make security` also
runs govulncheck and intentionally fails if the tool is absent. A missing scanner
is not a successful vulnerability assessment. Scanner source-processing must
also support the application's Go version. The user-installed v1.8.0 scanner
built with Go 1.26.9 failed to load this Go 1.27 module; rebuilding the same pinned
scanner with Go 1.27.2 in a private temporary directory succeeded and reported no
vulnerabilities. The user-installed executable was not overwritten. Temporary
tools may disappear between sessions; verify availability/version rather than
assuming a previous `/tmp` installation still exists. The earlier
Go 1.27.1 scan reported eight reachable
standard-library findings and exited nonzero; imported/module-only findings were
reported separately. The module now requires Go 1.27.2, which the advisories name
as the fixed version. On 2026-10-09, rescanning with Go 1.27.2 returned
"No vulnerabilities found" (exit 0). Go 1.27.1 with GOTOOLCHAIN=local refuses this
module instead of building vulnerable binaries. Rerun security checks for every release;
a clean scan covers the current database/toolchain, not unknown vulnerabilities.
Static reachability is not confirmation that every reported server-side
issue is exploitable in this HTTP-client application. Dependency currency remains
a release gate.

Default tests need no live credentials, make no real AWS service calls and create
no billable resources. Synthetic SDK HTTP boundaries exercise serialization,
signing and response parsing, not IAM enforcement. In-memory TLS/net.Pipe fixtures
exercise real TLS and streaming without OS listeners. Public synthetic CA files
are temporary test inputs; generated private keys stay in memory. Linux PTY tests
exercise terminal state, signals and no-echo MFA with controlled subprocesses.

Tests validate allowlisted diagnostics, ownership, secret redaction, command
quoting/result semantics, malformed protocol/control input, bounds, retries,
backpressure, shutdown and cleanup. Race detection is necessary, not proof that
every real interleaving or resource failure is covered. Documentation tests check
policy/config examples and repository-local links; they do not exercise policies
against AWS or validate external websites.

The private encrypted protocol tests use synthetic data keys and an in-memory
agent, not AWS KMS. They verify legacy/current context-challenge responses,
preparation failure redaction, encrypted challenge before readiness, directional
application payloads, ciphertext replay/retransmit preservation and key-reference
release on failure/shutdown without plaintext downgrade. FuzzKMSParameters tests
bounded selected-key/context parsing. The private SDK adapter now adds mock and
signed synthetic-HTTP GenerateDataKey tests for selected config/context, bounds,
plaintext clearing, fixed failures and disabled SDK payload logs. Authenticated
document/Connect integration has synthetic TLS coverage: selected-key mismatch,
early completion, KMS denial/setup cancellation, plaintext rejection and encrypted
bidirectional/owned-EOF success. No live AWS/KMS proof is asserted.

## Explicitly opted-in testing

The listener package has a real OS loopback bind/conflict/accept test:

```sh
SSMH_TEST_TCP=1 go test ./internal/forward -run TestListenRealTCP -count=1
```

It binds only TCP4 loopback and creates no AWS resources. After user-enabled
network access, it passed real bind/conflict/accept checks. That does not prove
live AWS or complete forwarding interoperability. Do not enable it where the temporary local listener
is inappropriate.

The CLI has composed shell/command-path TLS tests using synthetic credentials and
API/agent replies:

```sh
SSMH_TEST_TCP=1 go test -race ./internal/cli -run '^TestNative(Shell|Command)TLSComposition$' -count=10
```

It runs real SDK selection/signing, CLI document/session ownership, production
native Connect, the command result receiver and termination against a local TLS
peer. Plain/encrypted stdout/stderr/status, KMS denial, corrupted ciphertext,
missing status, cleanup denial and WebSocket HTTP 403 are checked. A denied
upgrade must return local failure without waiting for setup expiry, emit no
application bytes or response-body secrets, skip KMS and terminate the owned
session using a fresh context. No live AWS, compiled-executable
or remote TTY/application behavior is proven. The shell case uses the production
terminal loop with pipe input, default-document preservation, handshake-free
first output, ANSI/UTF-8 fidelity, Ctrl+C/EOF bytes, owned close, network loss and
cleanup denial or upgrade refusal. It does not test raw TTY, resize or physical-key behavior.
Default tests skip before credentials or sockets; these open only temporary
local synthetic listeners.
Normal authenticated shell closure plus successful local shutdown now skips a
redundant TerminateSession; the composed tests assert zero termination calls on
that path. The cleanup-denied shell fixture now drops transport without a closure
notification, proving failures still invoke explicit termination. Command
cleanup semantics are unchanged.

The compiled-binary variant exercises the same cases without injecting loader,
SDK, transport or terminal dependencies:

```sh
SSMH_TEST_TCP=1 go test -race ./internal/cli -run '^TestNativeExecutableTLSComposition$' -count=3
```

It builds the actual native-host executable and gives the child only explicit
synthetic credentials/configuration. A local CONNECT proxy tunnels the exact
selected regional service hosts to the synthetic TLS server. The child trusts
an owner-only temporary public test CA; private TLS keys remain in memory and
certificate verification stays enabled. No service endpoint override, production
test switch, AWS call or host AWS profile is used. Exit statuses and top-level
stderr diagnostics are checked along with session/stream/cleanup behavior.
This still does not prove live AWS, ARM64 runtime or remote TTY/application behavior.

The private plugin credential relay also has opted-in OS socket tests:

```sh
SSMH_TEST_TCP=1 go test -race ./internal/transport/plugin -run 'CredentialRelay|CredentialListener|CredentialConnection|ChildEnvironment' -count=1
```

These use synthetic credentials only and verify local authentication, actual SDK
decoding, cancellation, listener closure and clean child SDK provider selection.
Offline handler/connection/subprocess tests run
by default. No official plugin or live AWS is involved; the CLI does not start
this relay. See [relay boundaries](plugin-backend.md).

A Linux-only optional native suite now exists in `tests/integration`. It is not
run by ordinary verification: each live case skips before credential resolution
unless `SSMH_TEST_AWS` explicitly selects its operation. An invalid opt-in or
missing configuration fails without authenticating. The suite has **not been run
against AWS**; its existence and passing offline guards do not establish live
interoperability. Get approval for an existing target and exact test scope first.

Every operation requires `SSMH_LIVE_INSTANCE` (an explicit EC2 ID, not a Name),
`SSMH_LIVE_REGION`, and `SSMH_LIVE_ACCOUNT` (expected twelve-digit account).
Optional `SSMH_LIVE_PROFILE` and `SSMH_LIVE_ROLE_ARN` select SDK profile/explicit
role; otherwise the standard SDK chain applies. Use approved temporary credentials
already usable without MFA prompts. No credentials belong in these test variables,
command arguments, transcripts or fixtures. The same selected config is retained
for the STS account guard, complete EC2/SSM prerequisites and session/channel APIs.
An inaccessible identity or account mismatch prevents any session start; unlike
CLI check, denied STS metadata cannot satisfy this test safety guard.

This example uses synthetic placeholders; replace them only with approved values:

```sh
SSMH_TEST_AWS=check \
SSMH_LIVE_INSTANCE=i-0123456789abcdef0 \
SSMH_LIVE_REGION=ca-central-1 \
SSMH_LIVE_ACCOUNT=123456789012 \
SSMH_LIVE_PROFILE=approved-test-profile \
go test ./tests/integration -run '^TestLiveNativeCheck$' -count=1 -timeout=2m
```

`check` reads identity, EC2 state, SSM registration and the default shell document;
it starts no session and does not test session permissions. Selecting `shell`
instead and running `TestLiveNativeShell` authorizes one native shell with a fixed
nonce `printf` and `exit`, using redirected input. A split marker avoids mistaking
terminal input echo for command output. This is not a live TTY/resize/signal test.

`shell-tty` / `TestLiveNativeShellTTY` is a separate opt-in for a private Linux
PTY, not a change to the redirected-input `shell` operation. It requires approval
to run remote `printf`, `stty size`, `sh` and a bounded `sleep 30`, then send Ctrl+C
and Ctrl+D. It installs nothing and changes no remote configuration. The default
shell/session policy must support these commands and ordinary EOF termination.
It checks initial 30x90 and resized 41x105 remote dimensions after a real local
SIGWINCH, interruption without closing the client, EOF completion, and full
local terminal-state restoration. The developer's terminal is never made raw.

Use the same approved ID/region/account/profile variables above, select
`SSMH_TEST_AWS=shell-tty`, and run:

```sh
go test ./tests/integration -run '^TestLiveNativeShellTTY$' -count=1 -timeout=2m
```

Ten-second phases, at most ten probes for each size, and private per-probe 1 MiB
capture bound this test. Split markers prevent command echo from satisfying the
output check. Test cleanup joins terminal workers before owned AWS termination
and compares complete termios state even after a controllable failure. Offline
real-PTY harness tests cover these local mechanics with a synthetic channel;
they do not prove remote behavior. This live operation has **not been run**.
External SIGINT/SIGTERM, full-screen applications and the complete CLI process
are not covered by this case.

`command` / `TestLiveNativeCommand` additionally requires
`SSMH_LIVE_COMMAND_DOCUMENT` naming an existing approved non-elevated
NonInteractiveCommands document with separate output and unchanged String command
parameters. It runs fixed nonce stdout/stderr probes and exits 37; typed status and
stream separation are asserted. It creates or changes no document. See
[document compatibility](remote-commands.md).

`forward` / `TestLiveNativeForward` requires `SSMH_LIVE_FORWARD=18080:12345`;
`forward-host` / `TestLiveNativeForwardHost` requires, for example,
`SSMH_LIVE_FORWARD=18080:approved-echo.internal:12345`. These values are placeholders.
The destination must already be an explicitly approved dedicated TCP echo service:
the tests send generated bytes over three simultaneous streams. Do not aim them
at databases, administrative APIs or arbitrary production ports. Tests install no
echo service and provision no AWS resource. The local port must be nonprivileged,
available and binds only 127.0.0.1; a conflict fails before AWS authentication.
Required native agent/documents/permissions remain the normal forwarding ones.

Select exactly one operation per invocation; other live cases skip. Tests bound
setup to 30 seconds, the whole native run to 90 seconds, initial forwarding bind
to five seconds, and fresh owned-session termination to ten seconds. They join
channel/socket workers before AWS cleanup and report cleanup failure without
claiming that no residual session can remain after failure or abrupt termination.
Only process-owned session IDs are terminated; no discovery-wide cleanup occurs.
The suite does not create billable resources, but existing session logging/data
transfer can incur costs and approved shell profiles may have side effects.

Redirected output is captured only in private in-memory pipes, limited to 1 MiB
per stream; overflow cancels the operation and collectors are joined. The PTY
case uses its private master with a 1 MiB bound per probe. Test failure messages
omit remote output, auth objects, signed URLs and raw SDK errors. Nothing writes
transcripts to disk. AWS/agent logging settings remain unchanged. The suite tests
production libraries/native transport, not the complete executable CLI lifecycle,
plugin backend or ARM64 runtime. The separately selected shell-tty case extends
the library path to real terminal behavior but remains live-unverified; it does
not run the complete CLI executable. Record each actual
selected operation/result before making any live-validation claim.

Existing fuzz targets live beside the parsers/state machines. Run selected
targets with bounded fuzz time and constrained parallelism as needed; they must
not depend on AWS. A fuzz seed/success is evidence only for that target and inputs,
not a comprehensive audit or proof that an unimplemented feature works.

## Review and release gates

Review changed source for exposed secrets, changed privilege/identity, public
binding, disabled TLS, local command execution, unsafe parsing and incomplete
cleanup. Compare every affected CODEX entry with actual files and behavior. Keep
planned components clearly marked planned; do not create empty placeholders to
satisfy the proposed tree. See [architecture](architecture.md) for current ownership
and [security](security.md) for trust boundaries/limitations.

Before a release, complete the remaining plugin capabilities,
run vulnerability/dependency review, verify actual OS/network/agent behavior,
test both target architectures, and document residual limitations. Native KMS
shells/commands have synthetic tests; forwarding remains refused. Never present TLS as that additional KMS
feature. Plugin launch still requires reviewed identity/refresh/logging controls.
Release build success alone does not satisfy those gates.
The [PROMPT acceptance audit](acceptance.md) maps all requested sections/options
and numbered acceptance criteria to local evidence and remaining live/plugin
gates. Use it alongside source review, not as a substitute for executing a check.

Generated outputs are ignored. `make clean` removes only `bin/ssmh` and the two
named `dist/` binaries, not entire directories; it does not remove caches or source.
Do not replace that with broad recursive deletion. Never commit credential files,
tokens, private keys, sensitive logs or unnecessary generated binaries.
