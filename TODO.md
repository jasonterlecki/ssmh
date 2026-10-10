# ssmh continuation checklist

Handoff date: 2026-10-10. Source baseline before this handoff: `64f59a6` on
`main`. The full objective remains **implement the project described in
[PROMPT.md](PROMPT.md)**, not merely pass local tests. This is a development
client, not a production-ready release or a completion declaration.

Read [AGENTS.md](AGENTS.md) and the relevant parts of [CODEX.md](CODEX.md) before
changing anything. The detailed requirement/evidence inventory is
[docs/acceptance.md](docs/acceptance.md). Source code is authoritative when a
summary or older architectural paragraph disagrees with it.

## 1. Start on the new system

- [ ] Clone/fetch the repository normally and inspect `git status`, the current
  branch, upstream and latest commit. Preserve unrelated work. Do not force-push.
- [ ] Use Linux and a Go toolchain satisfying the current `go.mod` minimum
  (currently Go 1.27.2). Confirm `go version`; do not downgrade the module to use
  an older local toolchain. The old machine's `/snap/go/current/bin/go` workaround
  is machine-specific, not a portable requirement.
- [ ] Use locally configured AWS credentials/profile or a fresh supported login
  on the new machine. Do not transfer credentials, SSO caches, tokens, private
  keys or raw session logs through Git.
- [ ] Obtain the actual approved instance ID, region and expected account
  privately from the owner. Previous live validation used an existing instance
  in `us-east-1` with profile `default`; identifiers are deliberately omitted here.
- [ ] Confirm the operations and target are still authorized on the new system.
  Prior shell/TTY approval does not authorize creating AWS resources, installing
  remote services, changing IAM/preferences or testing arbitrary production ports.
- [ ] Build a fresh executable from the checkout. `bin/` and `dist/` are ignored;
  a clone does not contain the old machine's built binaries.

```sh
go version
go mod download
go test ./...
go vet ./...
make build
make release VERSION=dev
./dist/ssmh-linux-amd64 --help
```

Use the ARM64 executable on ARM64. `go mod download` needs network access or an
existing module cache. `make verify-release` needs cached dependencies and make.
No AWS CLI or Session Manager Plugin is required for native ssmh. AWS CLI is only
an optional independent tool for read-only session inspection below.

## 2. Preserve the established baseline

These capabilities already exist; do not rewrite them or classify them as absent
merely because the new machine lacks tools/credentials:

- Native authenticated SSM WebSocket shell, bounded codec/protocol sequencing,
  acknowledgements, TLS validation and terminal integration.
- SDK v2 provider chain, explicit profile/region, refreshable AssumeRole, MFA
  setup prompting, list/check JSON and exact EC2 Name resolution.
- Noninteractive command execution with authenticated document preflight,
  POSIX serialization, separate output and typed exit status.
- Both native forwarding modes with loopback listener, strict Port negotiation,
  bounded smux streams and joined worker cleanup.
- Optional `-ca` / `--ca-cert` PEM path. CLI selection overrides environment and
  profile CA selection; verification stays enabled. CLI reads are regular-file
  only and bounded to 4 MiB. Live custom-CA use remains unverified.
- Source-only Git commits/pushes after validated changes, as required by AGENTS.
- Static AMD64/ARM64 builds, isolated same-toolchain reproducibility checks,
  synthetic TLS/SDK/executable tests, real local PTYs, race and fuzz coverage.

Important existing lifecycle invariant: successful shell execution followed by
the real native channel's joined, authenticated owned-session EOF releases
ownership without redundant TerminateSession. Commands, forwarding, local
escape/cancellation and failed operations still explicitly terminate only owned
sessions with a fresh cleanup context. Never treat an AWS ValidationException as
success or skip cleanup merely because a socket disconnected.

### Actual live evidence, not a blanket reliability claim

The owner demonstrated basic executable shells and clean remote `exit`.
Subsequent approved agent-run validation on 2026-10-10 established:

- Read-only prerequisites and remote nonce shell: passed.
- Live library/native PTY test: **two failed size-probe attempts, then two passes**.
  The passes covered initial 30x90 and resized 41x105 remote sizes, Ctrl+C
  interrupting a bounded child without losing the shell, Ctrl+D completion and
  exact local termios restoration.
- Compiled `--check --json` and `--list --json`: passed for the approved target.
  Check correctly retained `session_permissions_verified=false`.
- All five newly started sessions appeared Terminated in AWS history; Active
  returned zero rows and no next token after the probes.

The first two PTY failures had terminal/channel shutdown errors labeled
`unclassified` by the diagnostics available at the time. They are unresolved.
Do not discard failed attempts, claim the whole suite always passes, or infer
remote full-screen/application behavior from raw-byte preservation.

Local compiled TLS/PTYS tests additionally verify real SIGTERM, SIGWINCH,
physical Ctrl+C/D bytes, Enter/~. escape, authenticated remote completion,
exit/cleanup call counts and complete restoration. These use synthetic AWS peers,
not live AWS, and are not a substitute for live executable coverage.

## 3. Highest priority: explain intermittent native failures

- [ ] Reproduce the live size-probe failure with a small, bounded, explicitly
  approved run. Keep every result, not only eventual passes. Stop and change
  approach after repeated identical failures; do not run an endless retry loop.
- [ ] Determine whether the fault is in the PTY probe/read deadline/marker
  collection, native input/resize/ACK ordering, channel shutdown, or the remote
  agent/session behavior. The cause is not yet known.
- [ ] Use the exact-label diagnostics in
  [tests/integration/native_test.go](tests/integration/native_test.go)
  (`liveFailureLabel`) and fixed native trace labels. The classifier is limited
  to reviewed exact errors, depth 8, 16 children per joined node and 64 visited
  non-nil nodes. Unknown text must not become diagnostic output.
- [ ] If another failure is still unclassified, add only a reviewed fixed label
  and regression test. Never dump raw SDK causes, frames, auth headers, session
  URLs/tokens, environment variables or remote terminal transcripts.
- [ ] Investigate the owner's earlier one-off `SSM payload digest mismatch`.
  Do not assume it caused the PTY failures: the available evidence does not
  connect them. Consult the pinned official protocol references in
  [docs/native-protocol.md](docs/native-protocol.md) when changing wire behavior.
- [ ] Fix the demonstrated cause with the smallest change and a reproducing test;
  add malformed/unexpected-input coverage if protocol handling changes.
- [ ] Establish a bounded passing verification run after the fix and record its
  exact scope and failure history. TLS, digest, ownership and sequence validation
  must remain enabled throughout.

Relevant code: `internal/transport/native/{message,protocol,stream,websocket}.go`,
`internal/terminal/{session_linux,io_linux}.go`,
[tests/integration/tty_linux_test.go](tests/integration/tty_linux_test.go).

## 4. Remaining native live acceptance

### Complete executable and terminal lifecycle

- [ ] Run the actual freshly built CLI against the approved live target in a
  controlled/private TTY, not only the library integration harness.
- [ ] Verify remote Ctrl+C/D, resize, normal `exit`, Enter/~. local disconnect,
  literal `~~`, external SIGINT/SIGTERM, local duration expiry and restoration.
- [ ] Exercise a controlled connection loss/setup failure; verify cleanup and
  safe errors without disabling network/TLS/protocol controls globally.
- [ ] Test ANSI/UTF-8, cursor/echo and an already-installed full-screen program
  where permitted. Do not install apps or invoke sudo automatically.
- [ ] Inspect owned-session cleanup after each tested exit/failure. Point-in-time
  inventory is evidence, not guaranteed cleanup after SIGKILL or machine loss.
- [ ] Validate live custom-CA selection and proxy behavior in an approved
  environment, including rejection of untrusted roots/hostnames without fallback.

### Authentication and discovery

- [ ] Verify explicit AssumeRole before subsequent EC2/SSM/channel operations
  with an approved role; confirm failures do not fall back to the original identity.
- [ ] Exercise needed deployment providers: SSO, profile-based roles, ECS/EC2
  credentials and credential-process configuration. Use synthetic tests for
  variants that cannot safely be exercised live; label that limit honestly.
- [ ] Verify MFA/refresh behavior where approved. Prompting deliberately stops
  after setup, so later refresh/cleanup requiring MFA may fail closed.
- [ ] Verify Name-based CLI selection, intended filters and ambiguous Names;
  pagination/duplicate live cases need an existing approved inventory, not
  unsolicited resource/tag creation. Single-target JSON success proves neither.
- [ ] Review least-privilege policy effectiveness for the actual identity and
  target. [docs/iam-policy.md](docs/iam-policy.md) records conflicting AWS
  OpenDataChannel scoping guidance; do not resolve it with blanket admin grants.
- [ ] Test other supported partitions only when required and approved. Endpoint
  overrides/other partitions are not implicitly supported by the current guards.

### Remote commands

- [ ] Identify an existing approved compatible NonInteractiveCommands document.
  It needs unchanged String command parameters, non-elevated Linux execution,
  separate output and empty separators; see
  [docs/remote-commands.md](docs/remote-commands.md).
- [ ] Run `TestLiveNativeCommand`: distinct nonce stdout/stderr and typed exit 37.
- [ ] Verify actual compiled CLI success/nonzero status, quoting/operators/Unicode,
  redirected output and interruption behavior. Never run user text through a
  local shell or substitute Run Command/SSH.
- [ ] Validate document-owned KMS shells/commands where an approved key and
  preferences already exist. Synthetic encrypted coverage is not live KMS proof.
  Do not change account preferences or create a key/document to make a test pass.

### Forwarding

- [ ] Obtain an already-running, explicitly approved dedicated echo destination
  for each mode; confirm agent capability and forwarding-document permissions.
- [ ] Run both `TestLiveNativeForward` and `TestLiveNativeForwardHost` separately.
  They send generated bytes through three simultaneous streams; never aim this
  probe at a database, admin API or arbitrary production port.
- [ ] Verify the compiled CLI's loopback bind, binary/multistream isolation,
  conflict reporting, shutdown, duration and owned cleanup against those services.
- [ ] Retain current full-close FIN semantics; independent end-to-end TCP
  half-close is not promised. KMS forwarding is refused, not implemented.

## 5. Portable live-test commands

Replace these synthetic placeholders privately with approved values. They are
not credentials. Do not commit real credentials or a machine-specific env file.

```sh
export SSMH_LIVE_INSTANCE=i-0123456789abcdef0
export SSMH_LIVE_REGION=ca-central-1
export SSMH_LIVE_ACCOUNT=123456789012
export SSMH_LIVE_PROFILE=approved-test-profile

SSMH_TEST_AWS=check go test ./tests/integration \
  -run '^TestLiveNativeCheck$' -count=1 -v -timeout=2m
SSMH_TEST_AWS=shell go test ./tests/integration \
  -run '^TestLiveNativeShell$' -count=1 -v -timeout=2m
SSMH_TEST_AWS=shell-tty go test ./tests/integration \
  -run '^TestLiveNativeShellTTY$' -count=1 -v -timeout=2m
```

Run only approved operations. Optional `SSMH_LIVE_ROLE_ARN` must name an approved
role. Command and forwarding require additional explicit configuration:

```sh
SSMH_TEST_AWS=command SSMH_LIVE_COMMAND_DOCUMENT=ApprovedCommandDocument \
  go test ./tests/integration -run '^TestLiveNativeCommand$' -count=1 -v -timeout=2m
SSMH_TEST_AWS=forward SSMH_LIVE_FORWARD=18080:12345 \
  go test ./tests/integration -run '^TestLiveNativeForward$' -count=1 -v -timeout=2m
SSMH_TEST_AWS=forward-host SSMH_LIVE_FORWARD=18080:approved-echo.internal:12345 \
  go test ./tests/integration -run '^TestLiveNativeForwardHost$' -count=1 -v -timeout=2m
```

Setup is bounded to 30 seconds; whole live operations to 90 seconds; fresh AWS
cleanup to 10 seconds. Default tests skip live operations before credentials.
The live suite does not currently accept a separate CA flag through its env gate;
use supported SDK CA configuration or the compiled CLI for that verification.

If AWS CLI is installed, inspect Active sessions without printing tokens:

```sh
aws ssm describe-sessions --state Active \
  --filters "key=Target,value=$SSMH_LIVE_INSTANCE" \
  --region "$SSMH_LIVE_REGION" --profile "$SSMH_LIVE_PROFILE" \
  --query '{sessions:Sessions[].{status:Status,start:StartDate},nextToken:NextToken}' \
  --output json
```

Also correlate History with the probes' times privately. Handle pagination; do
not mistake an empty page with a next token for complete inventory. Do not
terminate other sessions returned by discovery. If testing an assumed role,
ensure independent inspection uses an appropriately authorized identity; a CLI
source profile is not automatically the application's assumed identity.

## 6. Incomplete implementation: official plugin backend

`--backend plugin` is parsed but refused before authentication. `auto` selects
native only. Installing `session-manager-plugin` does not enable the backend and
does not unblock native testing. See
[docs/plugin-backend.md](docs/plugin-backend.md) for reviewed upstream constraints.

Implemented primitives already cover version preflight, private owned-response
handoff, selected-provider credential encoding, an authenticated loopback relay,
isolated child environment and protected disabled-logging preflight. There is
no operational session launcher/process lifecycle or CLI backend selection yet.

- [ ] Review the actual supported official binary/source version on the new
  system; installation/provenance and trusted PATH/stty need explicit review.
  Prior source analysis pinned `7cde6748cc6cffbc69546b4de08e603cd39be6d8`;
  do not assume an installed version has identical behavior.
- [ ] Establish effective disabled logging before token handoff, using the
  existing read-only protected-config check. Linux plugin logging is installation-
  wide/reloadable; raw child errors/reconnect logs may expose auth URLs. Never
  auto-edit global logging or treat parent redaction as child log suppression.
- [ ] Integrate bounded environment handoff without tokens/URLs in argv or disk.
- [ ] Preserve the parent's selected SDK identity and refresh via the relay;
  pass no original profile to a separately loading child. Prevent alternative
  credential sources and leaks/proxying of relay authentication.
- [ ] Transfer resolved CA/proxy settings faithfully; do not guess from a new
  credential/configuration chain or disable verification for compatibility.
- [ ] Enforce reviewed secure endpoint behavior during both initial connection
  and resume. The reviewed upstream resume path does not apply the same URL
  validator; do not declare this solved by validating only the initial response.
- [ ] Implement structured launch, terminal ownership/restoration, signals,
  bounded shutdown/reaping, safe output semantics and parent-owned AWS cleanup.
- [ ] Implement explicit backend routing/capability checks and actionable missing-
  dependency errors only after these gates are verified. Never silently change
  requested operation, identity, security policy or restart a remote command.
- [ ] Validate both plugin forwarding modes, selected-provider refresh/failure,
  logging policy and KMS compatibility against the real supported plugin. The
  reviewed plugin lacks a newer agent random-context acknowledgement; do not
  weaken agent policy to enable it.
- [ ] Add regression/integration tests for every enabled path; document external
  dependencies and unsupported capabilities precisely. If a gate cannot be met,
  report the exact limitation instead of enabling an unsafe or mock backend.

## 7. Release/hardening gates

- [ ] Run scoped tests during changes; run the full applicable gates for final
  significant changes/release. Record actual commands/results and skips.

```sh
go test ./...
go vet ./...
go test -race ./...
SSMH_TEST_TCP=1 go test -race ./...
go mod verify
govulncheck ./...
make release VERSION=dev
make verify-release VERSION=dev
```

- [ ] Use a compatible installed govulncheck; report absence/failure rather than
  claiming a clean scan. The old machine's private /tmp installation is not in Git.
- [ ] Review dependencies/security advisories rather than blindly upgrading pins.
  Earlier scans were clean with Go 1.27.2; that is dated evidence, not a perpetual
  security guarantee.
- [ ] Run relevant bounded parser/state-machine fuzz targets after related changes;
  use [docs/development.md](docs/development.md) for target discovery/workflow.
- [ ] Verify AMD64 and ARM64 artifacts and same-input/toolchain reproducibility.
  Execute ARM64 on an actual approved ARM64 Linux system; cross-compilation is
  not runtime evidence. Native binaries must not require Go/CLI/plugin installed.
- [ ] Finish release security review: secret redaction, exact TLS/endpoints,
  credential identity/refresh, permissions, document-version trust/races, session
  ownership, protocol/memory bounds, local injection, loopback and joined cleanup.
- [ ] Confirm user documentation and working examples for the completed features.
  Preserve limitations: SDK-managed cache writes, regular-file I/O cancellation,
  admin-trusted document/alias changes, unsupported key expressions/partitions,
  and no restoration guarantee after SIGKILL.
- [ ] Obtain owner decisions for any license/release publication. LICENSE and
  optional lint config/picker are not reasons to invent policies or add scaffolding.
- [ ] Audit every PROMPT requirement and all 18 acceptance criteria against
  current evidence before marking the goal complete. Do not substitute synthetic
  or narrow evidence for a broader requested result.

## 8. Working rules for the next agent

Keep a compact requirement/result/next-proof ledger, using this checklist and the
acceptance map. Reuse unchanged instructions and completed test evidence. Do not
reread the entire repository or perform a full audit at every continuation.
Prefer concrete fixes/required integration over more synthetic cases or status
rewrites once the relevant local boundary is covered. Ask once for missing
authority; work on independent authorized tasks, not repeated blocker polling.

After a real validated change: synchronize CODEX and affected docs, review for
secrets/security regressions, stage explicit task-owned paths, commit and normally
push the current configured upstream under AGENTS Section 21. Never include
binaries, credentials, transcripts or AI attribution. Report publication failures
without force-pushing or changing Git configuration.

This handoff is not the internal goal-state JSON and contains no live target IDs,
account identifiers or authentication material. It can travel with the source;
private environment and approval details must travel separately.
