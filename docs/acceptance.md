# PROMPT implementation and acceptance audit

This is an evidence map for [PROMPT.md](../PROMPT.md), not a declaration of
completion. The full requested objective remains open. Inspect current source and
rerun checks after changes; passing synthetic tests does not establish AWS
interoperability, IAM effectiveness or remote terminal behavior.

The offline [inventory check](../tests/documentation/acceptance_test.go) catches
omitted numbered sections, acceptance criteria and registered CLI options. It
does not validate assessments or turn documentation into implementation evidence.

Evidence classes used below:

- **Local**: implemented behavior supported by source and offline/controlled OS
  tests or actual build/executable checks. This does not prove live AWS behavior.
- **Live missing**: implementation exists, but the requirement's AWS/remote scope
  has not been exercised. Do not promote it to complete from local evidence.
- **Incomplete**: required implementation or integration is absent.
- **Optional**: the prompt allows omission; this is not a substitute for another
  mandatory requirement.

### Owner-run live evidence

The owner supplied executable output showing a native shell on an existing EC2
instance in us-east-1 with `--profile default`. After the remote-completion cleanup
fix, both debug and normal invocations reached a shell and returned cleanly on
remote `exit`. Debug output showed SDK shared-profile selection, successful
EC2/SSM prerequisites and StartSession, verified owned-session EOF, joined socket
closure and skipped redundant TerminateSession. This is owner-reported live
evidence, not an agent-run integration test or proof of every acceptance item.
The output predates the CA-option change; live custom-CA behavior is not verified.
No transcript, authentication material or instance/account identifiers are stored
here. The earlier one-off payload digest mismatch remains unexplained; its
validation was not relaxed. Repeated startup, Ctrl+C/D, resize, full-screen apps,
local escape/signals, restoration and post-exit AWS session inventory still need
controlled evidence. AssumeRole, discovery/list, commands and both forwarding
modes remain live-unverified. The optional automated AWS suite has not run.

## Requirements by prompt section

| Section / explicit requirement | Current evidence and limits | Assessment |
| --- | --- | --- |
| Objective: IAM-authenticated SSM shell, not SSH; no daemon, keys, port 22, public IP, bastion or AWS CLI transport | [CLI composition](../internal/cli/root.go), [native socket](../internal/transport/native/websocket.go), [session ownership](../internal/ssm/session.go). No SSH/CLI transport branch; owner-run basic live shell demonstrated as scoped above. | Local; limited live evidence |
| 1: Go/native Linux AMD64 and ARM64; single executable; no Python/Node/Java runtime | [go.mod](../go.mod), root/cmd wrappers, static ELF checks in [release tests](../tests/build/release_test.go). ARM64 is cross-built, not executed. Optional SDK credential-process programs are user configuration, not transport dependencies. | Local; ARM64 runtime missing |
| 1: maintained SDK v2 EC2/SSM/STS/shared providers; minimal dependencies | Pinned [module graph](../go.mod), [SDK loader](../internal/aws/client.go). Targeted authentication patch reviewed; broader dependency currency remains a release review item, not a latest-version claim. | Local |
| 1: standard builds, reproducibility, linker version, Makefile | Root `go build`, actual Makefile releases, two source locations per architecture, static/stripped/trimpath metadata and native version/help probes in release tests. Reproducibility is same input/toolchain only. | Local |
| 2A: StartSession; ID/URL/token; authenticated WebSocket; framing; handshake; input/output; ACK/sequence; resize; termination/disconnect | [Session](../internal/ssm/session.go), [codec](../internal/transport/native/message.go), [protocol](../internal/transport/native/protocol.go), [channel](../internal/transport/native/stream.go), socket and [terminal loop](../internal/terminal/session_linux.go). Independent wire/TLS/ordering/retry/stream/PTY tests and owner-run basic agent shell; resize/failure/reliability proof remains missing. | Local; limited live evidence |
| 2B: official plugin fallback when native cannot be reliably validated; SDK authentication/start; response handoff; terminal; cleanup; discovery/install error | [Plugin primitives](plugin-backend.md) include preflight, response/credential codecs, authenticated relay and explicit child environment, but no session launcher or CLI selection. They are not a backend. Effective logging, child provider/CA integration, output, reconnect and process lifecycle gates remain unresolved; reviewed Linux plugin also requires trusted stty. | Incomplete |
| 3: GNU CLI; mandatory `--instance/-i`; ID; optional Name; explicit ambiguity | [Flags/parser](../internal/cli/flags.go), [validation](../internal/config/config.go), [resolver](../internal/ec2/resolver.go), parser/resolution tests. Exact Name duplicates require an ID; no arbitrary selection. | Local |
| 4: `--profile/-p`; env/shared config/shared credentials/SSO/EC2/ECS/role/credential-process chain | SDK LoadDefaultConfig preserves provider selection; environment/profile and SSO/login cache tests exercise selected SDK behavior. Actual SSO login, task/instance identity and credential-process deployments are not live-tested. | Local; deployment evidence missing |
| 4: `--arn`; AssumeRole before later APIs; refresh; no fallback; `--session-name`, unique generated default, `--external-id` | [Assume](../internal/aws/client.go), `TestAssumeConfigurationRefreshAndFailure`, CLI selected-config tests. Requests/cache refresh tested with synthetic STS; real role trust/authorization unverified. | Local; live missing |
| 4: `--mfa-serial`, `--mfa-token`, preferred secure interactive prompt that does not steal shell input | [MFA prompt](../internal/terminal/mfa_linux.go), [CLI gate](../internal/cli/mfa.go), real controlled PTY/subprocess and refresh tests. Prompting is disabled after setup; later refresh/cleanup needing MFA can fail. | Local; live missing |
| 5: `--region/-r`; explicit over SDK config/env; no arbitrary default; commercial and other partition design | Loader/validation tests; strict commercial/China/GovCloud stream hosts in session validator. Other partitions/custom endpoints unsupported rather than weakened. Actual partition sessions untested. | Local; live missing |
| 6: default interactive shell; raw mode; Ctrl+C/D; SIGINT/TERM; remote closure/network/setup failures; full restoration; explicit Enter `~.` and literal `~~` | [Terminal](../internal/terminal/session_linux.go), state/stream/escape sources and PTY/subprocess tests. Opt-in [composed TLS test](../internal/cli/native_command_tls_test.go) runs SDK/native/production terminal loop/default-document/owned cleanup with pipe input, ANSI/UTF-8 and Ctrl+C/EOF bytes, normal close/network loss/cleanup denial. It is not a compiled CLI, physical TTY or real agent test. EOF sends one Ctrl+D. Restoration is attempted on controllable paths, not promised after SIGKILL. | Local; live missing |
| 6: ANSI/colors/cursor/echo/UTF-8; interactive/full-screen apps (`ls`, `top`, `htop`, `vim`, `nano`, permitted `sudo -i`) | Raw-byte transport and terminal output preservation tested, not real application behavior. No client-invoked sudo. A controlled live TTY/app exercise is still needed. | Live missing |
| 7: `--command/-c`; supported Session document; no SSH/Run Command; remote quoting including spaces/quotes/operators/Unicode | [Serializer](../internal/command/quote.go), [document preflight](../internal/ssm/documents.go), CLI command tests; remote `/bin/sh -c`, never local evaluation. Default AWS document can be incompatible and is refused; an approved compatible document may be necessary. | Local; live missing |
| 7: noninteractive separate stdout/stderr; reliable status; distinguish remote failure/setup/auth/interruption | [Receiver](../internal/command/execute.go), [typed status](../internal/command/exitcode.go), CLI status/error mapping. Opt-in [composed TLS test](../internal/cli/native_command_tls_test.go) runs actual SDK/native/result/owned cleanup together for plain/KMS data and denial/corruption/missing-status/cleanup errors. It is in-process, not compiled CLI or live AWS. Status is invalidated by missing/duplicate status, incomplete output, interruption or cleanup failure. Negative/signal agent status is unknown. | Local; live missing |
| 8: `--list`; `--state`, `--tag`, `--name`, region; ID/Name/state/SSM/platform/private IP/region columns; `--json`; full EC2/SSM pagination and registration join | [Discovery](../internal/ec2/discovery.go), [SSM inventory](../internal/ssm/status.go), [list](../internal/cli/list.go), [formatting](../internal/cli/output.go). Signed SDK XML/JSON fixtures test complete/all-or-error joins and clean ASCII JSON. Real inventory unavailable. | Local; live missing |
| 8: optional interactive picker with no supplied instance | Not implemented; prompt explicitly makes it optional. Mandatory target validation remains. | Optional |
| 9: exact Name preference; unique complete match; duplicates require selection; SSM verification; useful not-found diagnostic | Resolver waits for every page; stopped/offline duplicates are not discarded. [Resolution tests](../internal/cli/resolution_test.go) cover all four session modes before session-client creation. | Local; live missing |
| 10: `--forward/-L LOCAL:REMOTE`, AWS-StartPortForwardingSession; remote-host syntax/document | [StartForward](../internal/ssm/forward.go), [Port negotiation](../internal/transport/native/port.go), [smux](../internal/transport/native/mux.go), [serving](../internal/transport/native/forward.go). Fixed documents/exact parameters and destination handshake, not shell tunneling. Both live echo probes unexecuted. | Local; live missing |
| 10: loopback default; port validation/conflict; graceful shutdown; address/target report; real binary protocol or plugin fallback | [Listener](../internal/forward/listener.go), config/CLI/mux tests, opted-in OS bind/conflict/accept test. Multiplexed workers are bounded/joined; no public/alternate port or elevation. FIN is full close, not independent TCP half-close. | Local; live missing |
| 11: `--document` optional/default AWS shell; `--reason` unchanged; no preference substitution | StartShell preserves default selection; StartCommand separately validates command policy/preferences/literal key. Type-bound owned KMS capabilities retain selected SDK config and require encrypted challenge. Synthetic TLS/SDK verifies shell data and command stdout/stderr/typed status; CLI tests verify owned cleanup. Unknown/parameterized keys fail; logging/run-as unchanged and document admins trusted. | Local; live missing |
| 11: `--timeout` default 30s; `--duration`; duration does not override AWS policy | Shared setup budget and separate post-Start lifetime in [connect](../internal/cli/connect.go); deadline/duration/cancellation/fresh cleanup tests. AWS policies remain authoritative. | Local; live missing |
| 11: `--backend native/plugin/auto`, default auto, prefer validated native; only available fallback; no security/operation downgrade | Parser accepts all values; auto uses native, explicit plugin is refused before auth. No fallback is enabled. The required operational plugin path is absent and native live validation is missing. | Incomplete |
| 12: `--check -i`; credentials, permitted STS identity, region, EC2 existence/running, registration/Online, backend; actionable report without permission-test shell | [Check](../internal/cli/check.go), signed SDK read-only tests. Explicit STS metadata denial may report unavailable using the same config; other failures stop. Reports say prerequisites only and session_permissions_verified=false. Native default shell compatibility only; plugin unavailable. | Local; plugin incomplete; live missing |
| 13: `--verbose/-v`, `--debug`, `--quiet/-q`; minimal default, provider/region/resolution/stages/termination; protocol state/API timing/retries; clean stdout; no secrets | [Diagnostics](../internal/cli/diagnostics.go), [metrics](../internal/aws/metrics.go), [trace](../internal/transport/native/trace.go), [provider labels](../internal/aws/credentials.go), signed SDK/blocked-writer/redaction tests. Fixed bounded summaries, not payload dumps or every SDK operation. | Local |
| 14: no credential persistence by app/secrets/TLS bypass/IAM bypass/SSH/elevation/local shell injection/public default bind | Source boundaries above; [safe errors](../internal/logging/errors.go), source/redaction/ownership/TLS/injection tests. SDK credential cache writes and trusted configured credential_process are documented exceptions to disk-free/process-free assumptions, not an app credential store. | Local security evidence, not certification |
| 14: respect Session Manager preferences/policies; restrictive generated files; distinguish shell/SSH-over-SSM/forwarding logging visibility | Document preflight does not rewrite settings; SDK login new-file policy is owner-only, existing modes unchanged. [Security guide](security.md) describes visibility and limitations. Live effective preferences/IAM/logging remain unverified. | Local; live missing |
| 15: complete lifecycle stages 1–11; process-owned termination; contexts; joined resources; bounded transient retries; never restart disconnected command | Loader/resolver/SSM/connect/native/terminal ownership; SDK max 3 attempts; bounded unchanged-frame retransmission, no reconnect/replacement command. Fresh 10s owned TerminateSession after local shutdown. Synthetic failure/cancellation cleanup evidence is not a no-residual-session live guarantee. | Local; live missing |
| 16: Linux maintained terminal equivalent; TTY detection/raw only when needed/full restoration/SIGWINCH/dimensions/raw output/pipes/EOF/SIGINT/TERM; redirected command output clean | x/sys ioctl/private Stream implementation, real PTYs and synthetic channel/command tests. Pipe/TTY cancellation is bounded; regular-file kernel I/O may block. No client-generated ANSI in JSON/command output. | Local; live missing |
| 17: useful missing-instance/credential/target/role/permission/channel errors; meaningful documented process statuses | Fixed allowlisted errors; usage=2, local failure=1, cancellation=130, sole verified remote status propagated. Raw secret-bearing SDK causes are not printed. Broken reporting cannot bypass cleanup. [Troubleshooting](troubleshooting.md). | Local |
| 18: `--help/-h`, `--version`; all supported options, Go version/platform, linker release version | Actual compiled help/version and executable subprocess tests, [version](../internal/version/version.go), release metadata checks. Help explicitly identifies unsupported plugin. | Local |
| 19: clean packages/interfaces at real boundaries; no unnecessary framework; inspect existing instructions | [Architecture](architecture.md), [CODEX](../CODEX.md), SDK/channel/terminal test boundaries. Root and cmd wrappers share app; no alternate session implementation or DI framework. | Local |
| 20: `make build/test/lint/clean/release`; two named dist files; static preference, version, install instructions, no Go runtime | Actual [Makefile](../Makefile)/release/ELF tests; README user-owned installation instructions. Clean removes only three exact generated binaries; no publishing/commit/install performed. | Local |
| 21: CLI/required options/region/profile/role/ID/Name/duplicate/pagination/readiness/lifecycle/cleanup/signal/quoting/status/forward/bind/error automated tests | Colocated package tests and executable/PTYS tests run without live credentials. Native codec/handshake/I/O/ACK/sequence/fragmentation/disconnect/timeout/malformed and fuzz targets exist; source-reference guides distinguish verified behavior. | Local |
| 21: optional explicit live suite; no billable resource creation in default tests | [Native opt-in suite](../tests/integration/native_test.go) and [guards](../tests/integration/guard_test.go); exact operation/ID/region/account gate. Default cases skip before credential resolution. No actual AWS run. | Local gate; live missing |
| 22: README items 1–15; prerequisites/agent/profile/endpoints/private VPC endpoints; least-privilege user policy and instance/document/own-session scope | [README](../README.md), authentication/IAM/security/discovery/command/forwarding/troubleshooting/development guides; offline policy/SSO-config/local-link tests. Resume is deliberately omitted because native does not use it. IAM OpenDataChannel scope conflict is recorded, not bypassed. Working live examples/policy efficacy unverified. | Local documentation; live missing |
| 23: basic/profile/role/both/region/Name/command/sudo/forward/remote-host/list/check/debug example workflows | All flags route to real implemented native/read-only operations except plugin. Basic ID/profile/region/debug shell has owner-run live evidence; other examples require approved scope and verification. Noninteractive `sudo -i` is not promised as an interactive root shell. | Local syntax/routes; limited live evidence |
| 24: dependency-order implementation phases 1–6; functional shell before advanced modes; mark incomplete native/plugin honestly | Existing code is real native transport, not mock production logic. Basic shell has owner-run live evidence plus synthetic end-to-end TLS/lifecycle/PTY evidence; broader live validation and plugin remain incomplete. | Incomplete final phase |
| 25: numbered acceptance criteria | Separate item-by-item table below. | Not achieved |
| 26: implementation rather than proposal; official protocol research; actual formatting/vet/test/build/race/both architectures; no placeholders/live claims/AI attribution; final feature/backend/dependency/artifact/limits/run report | Sources/tests/builds exist, protocol references in native guides, no production mock transport. Source changes are committed/pushed under owner authorization; release publication is separate. Final full-scope completion report must wait for unmet gates; development reports do not replace it. | Local; completion report pending |

## All named CLI options

The source of truth is Flags/Parse, not the sample help in the prompt. Current
compiled help covers these registrations and explains backend limitations:

| Group | Required names/aliases |
| --- | --- |
| Connection/authentication | `--instance/-i`, `--profile/-p`, `--region/-r`, `--arn`, `--session-name`, `--external-id`, `--mfa-serial`, `--mfa-token`, `--ca-cert/-ca` (`--ca` also accepted) |
| Execution | `--command/-c`, `--document`, `--reason`, `--forward/-L`, `--forward-host` |
| Discovery/check | `--list`, `--name`, `--state`, repeatable `--tag`, `--json`, `--check` |
| Runtime/diagnostics | `--timeout`, `--duration`, `--backend`, `--verbose/-v`, `--debug`, `--quiet/-q` |
| General | `--help/-h`, `--version` |

Parsing an option is not proof its backend is operational: `plugin` is accepted
syntactically and then explicitly refused before authentication. Empty command
and conflicting modes are refused, never silently changed into a shell.

## Numbered acceptance criteria (PROMPT section 25)

| # | Required outcome | Evidence / remaining proof |
| --- | --- | --- |
| 1 | `go build` succeeds | Actual root build in isolated source copy, not just package compilation. Local verified. |
| 2 | Linux AMD64 binary | Actual Makefile output, static stripped ELF machine/build inspection. Local verified. |
| 3 | Linux ARM64 binary | Actual cross-build and static stripped ELF inspection. Local verified; ARM64 runtime not inferred. |
| 4 | Help displays all supported options | Actual compiled root/cmd help parity; Flags registrations and executable tests. Local verified. |
| 5 | ID establishes an interactive SSM shell | Owner-run live executable reached a shell and returned cleanly on remote exit; see scope above. [Compiled native-host TLS composition](../internal/cli/native_executable_tls_test.go) supplies controlled executable failure/cleanup evidence, not real remote TTY proof. **Basic live shell demonstrated; broader TTY/reliability proof missing.** |
| 6 | Profiles work through SDK chain | Owner-run live default-profile shell; debug reports shared-profile selection. Actual SDK environment/shared-profile/SSO/login fixtures cover local selection. **Default profile demonstrated; other live provider deployments missing.** |
| 7 | Explicit ARN assumes role before connection | Synthetic STS/config/lifecycle fidelity. **Live AssumeRole and subsequent session missing.** |
| 8 | No SSH daemon/key/22/public-IP dependency | Native SSM path contains none; no SSH fallback. Local source evidence; private-instance live deployment missing. |
| 9 | Ctrl+C/D/resize/disconnect correct | Controlled PTYs/sequence/signal/channel tests; compiled TLS `shell/tty-sigterm` verifies initial and SIGWINCH-resized dimensions, physical Ctrl+C/D byte delivery without local exit, and actual SIGTERM with one owned cleanup. Separate opt-in [live PTY case](../tests/integration/tty_linux_test.go) checks remote size/control bytes but has not run. **Live remote TTY behavior missing.** |
| 10 | Terminal restored | Full termios comparisons and controllable failure tests; compiled TLS PTY cases verify exact restoration after actual SIGTERM, local Enter/~. escape and authenticated owned remote completion. The latter two return 0 with one/zero termination requests respectively. Live PTY case includes restoration after joined workers but remains unexecuted. **Live process/session restoration missing.** SIGKILL is not controllable. |
| 11 | No unnecessary active sessions after cleanup | Owner-run normal remote exit reports verified owned EOF and skips redundant termination; private successful-Start ownership, bounded fresh termination and failure tests cover other paths locally. **Controlled post-exit AWS inventory and local-disconnect/failure cleanup evidence still needed.** Cleanup remains best effort. |
| 12 | Discovery works | Actual signed SDK serialization/decoding plus complete bounded synthetic inventories. **Live inventory missing.** |
| 13 | Readable actionable errors | Fixed redacted messages, executable usage/error tests, troubleshooting guide. Local verified, not every AWS condition exercised. |
| 14 | Unit tests pass | Full default suite plus opted-in OS socket/race cases, including composed in-process and actual compiled native-host TLS sessions; live cases intentionally skipped. Local verified. |
| 15 | README working examples | Owner-run basic ID/profile/region/debug shell demonstrated. Syntax/routes/docs/local links and compiled synthetic cases cover other examples locally. Compatible-document/agent prerequisites explicit. **Other live example effectiveness missing.** |
| 16 | No AWS secret exposure | Allowlisted diagnostics/formatting/raw-error omission and synthetic redaction tests. Local reviewed; not a complete security certification or plugin-log guarantee. |
| 17 | Native has no external runtime dependency | Static ELF/release build and source transport review. Optional user-configured credential_process is a separate authentication prerequisite. Local verified. |
| 18 | Remaining compatibility dependencies documented | Plugin external executable, unsupported integration and all unresolved gates explicit. Documentation verified; **operational backend incomplete.** |

## Validation and what can unblock the remaining evidence

Run the exact local checks in [development](development.md), including full unit
and race suites, vet, module verification, available govulncheck, both release
builds and `make verify-release`. An opted-in loopback listener check verifies OS
binding/conflict/accept only. Formatting, compiler success or a clean scan is not
an IAM/session/terminal acceptance substitute.

Live tests require an explicitly approved existing EC2 ID, selected region,
expected account and usable profile/role credentials, plus approved operation
scope. The existing suite can check read-only prerequisites, a nonce shell,
separate-output command/status, or concurrent forwarding to a dedicated existing
echo service. Its redirected shell is **not** the complete executable/TTY/resize/
signal test, and it does not execute on ARM64. It provisions no target, document
or echo service and never broadens permissions/preferences to make a test pass.

Before claiming full completion:

1. Supply approved live scope and gather real shell/profile/role/discovery and
   owned-cleanup evidence; then exercise controlled real CLI TTY/application,
   signal/resize/restoration and both forwarding modes as approved.
2. Implement/verify the official plugin compatibility path under the documented
   logging, selected-identity/refresh, endpoint/replay and process/terminal gates.
   Do not auto-edit global plugin logging, install binaries or relax TLS/IAM.
3. Reconcile every remaining row with current evidence and complete release
   security/dependency review. Record limits without calling them implemented.

Missing approved live target/scope is an external authorization blocker. Missing
plugin launch is an implementation/security gate. Neither is resolved by full
filesystem/network access or by repeating passing offline checks.
