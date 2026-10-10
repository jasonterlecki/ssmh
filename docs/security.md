# Security model and deployment review

This describes the implemented native Linux shell/command/forwarding client, not a security
certification or the completed `PROMPT.md` application. Live AWS interoperability,
and release dependency review remain unverified. The earlier govulncheck scan
reported eight Go standard-library vulnerabilities with Go 1.27.1. The module
now requires patched Go 1.27.2, and the 2026-10-09 rescan reports no vulnerabilities.
Recheck before releases; this result is not a security certification.
Static findings are not proof of exploitability. Do not
treat this development build as production-ready.

## Assets and trust boundaries

Protect AWS credentials, MFA codes, SSO cache tokens, SSM session tokens and signed
URLs; remote input/output can contain equally sensitive application data. Account,
principal ARN, region and target ID are not authentication secrets but can still
be operationally sensitive. Verbose/debug diagnostics disclose selected metadata
to stderr; review it before sharing.

| Boundary | Implemented protection | Assumption or remaining exposure |
|---|---|---|
| Local invocation and configuration → SDK | Bounded CLI validation; SDK v2 credential chain; explicit role failure has no fallback | Local user, binaries, configuration and configured credential programs are trusted |
| SDK → AWS control APIs | Verified TLS, guarded signed endpoints, no redirects, bounded retries/timeouts | AWS authorization and trusted local CA/proxy configuration remain authoritative |
| AWS response → owned session | Validated session ID and exact regional stream host/path before token use | A response without a valid ID cannot safely be cleaned up |
| Authenticated channel → protocol state | Bounded framing, digest, sequence/acknowledgement and ownership checks | AWS service, target agent and authorized target administrators are trusted; framing checks do not make the target benign |
| Channel → local terminal/files | Private cancellable streams and controllable terminal restoration | Remote bytes are intentionally raw; terminal emulators and output destinations must be trusted |
| Session → cleanup API | Private process-created ownership and fresh cleanup context | Network/authentication loss or abrupt process death can leave a session active |
| Selected SDK provider → private plugin credential relay (not CLI-enabled) | Exact authenticated loopback GET, random authorization, bounded sockets/retrievals, uncached responses and fixed errors; explicit child environment excludes other credential sources | Plain local HTTP and child-environment authorization do not isolate secrets from the local user/OS; effective installed-child provider/CA integration and launch remain unfinished |
| Installed plugin logger → local files/output (not CLI-enabled) | Private read-only preflight requires root-owned protected fixed config and narrow disabled XML without exceptions/outputs | Not yet launcher-integrated; trusted root can change settings, installed binary semantics are not certified, and mixed raw child output remains unresolved |
| Document-owned KMS shell/command → SDK/native protocol | Selected SDK config, bounded one-use key request with owned IDs/random context, type-bound document capability, plaintext clearing, challenge before readiness, immutable encryption policy and ciphertext replay identity | Synthetic TLS/SDK proof only; forwarding/key expressions unsupported. Document/alias admins trusted; Go/SDK/crypto memory and copies are not guaranteed erased |

The client does not defend against a compromised local OS, a user able to read
its process memory, a replaced binary, malicious trusted credential configuration,
or an authorized administrator changing IAM, documents, agent or remote OS state.
Least-privilege IAM and OS configuration are deployment responsibilities; the
client never changes them automatically. See the [IAM guide](iam-policy.md).

## Authentication and secret lifecycle

Authentication uses AWS SDK v2 providers, not a parallel application credential
store. SDK-managed refresh is preserved. Explicit `--arn` selects only that role;
failure ends setup rather than continuing with the source identity. There is no
automatic role search. Identity diagnostics are read-only and do not establish
StartSession permission.

Shared configuration is a code-execution trust boundary: the SDK can execute a
configured `credential_process`. This is distinct from remote commands, which
the client never runs through a local shell. Protect shared files, SSO cache,
environment and configured executables from other users. SDK SSO refresh can
rewrite its existing cache while preserving its permissions; the application
does not repair permissive cache files. See [authentication](authentication.md).
New SDK login-cache files are requested with owner-only permissions; an inherited
unrestricted setting cannot weaken that application policy. Existing login/SSO
cache files keep their permissions and are not automatically hardened. SDK cache
writes remain distinct from application-owned credential persistence.

SSM transport material stays in memory and is exposed only to backend setup.
Formatted session objects redact it; diagnostics use fixed labels and selected
validated metadata rather than raw errors, requests, headers or provider objects.
Successful termination releases the session's token/URL references. This is not
secure erasure: Go/SDK strings, temporary buffers and process memory can retain
copies. Do not capture process dumps or enable external HTTP/header tracing when
handling real credentials. Local shell history and process inspection can also
expose commands or an explicit `--mfa-token`; prefer no-echo `/dev/tty` prompting.

MFA prompting is bounded by setup, clears queued input and restores saved terminal
settings. It stops permanently before remote I/O so later credential refresh
cannot consume remote input. A later refresh requiring another MFA code fails
closed, possibly preventing cleanup. No token is reused to bypass that failure.

## Network and protocol integrity

TLS certificate verification is never disabled. AWS API HTTP redirects and
configured custom service endpoints are refused. The signed-request guard requires
HTTPS, an AWS domain suffix and the default/443 port. Native stream validation is
stricter: exact regional `ssmmessages` host, expected session path, secure WebSocket
scheme and expected stream role. Commercial, China and GovCloud stream hosts are
supported; other partitions/alternate endpoints are not yet supported. Supported
HTTP proxy configuration remains in effect, not silently bypassed. Local trust
roots/proxy settings are part of the trust boundary. AWS_CA_BUNDLE/selected shared
ca_bundle are SDK-loaded, with environment precedence and explicit roots replacing
system defaults. Invalid bundles fail closed; configured CA files are trusted
local inputs, and SDK file reads/parsing have no application-added size bound.
Pre-resolution builder copies retain signed-endpoint and redirect guards through
connection selection, including direct/pooled requests; supported proxy behavior
is delegated, not bypassed. Captured SDK credential clients disable keepalives
to avoid uncloseable idle pools, while the returned client owns its guarded pool.
CA loading never disables certificate/hostname validation or changes identity.

Native WebSocket setup verifies the HTTP upgrade before submitting the session
token. Framing, known message types, lengths, payload digest, ordered delivery,
acknowledgement identity and owned-session close are checked. Payload hashes are
integrity checks, not an independent authentication mechanism; TLS and AWS session
authentication establish channel trust. Malformed messages end the operation.

WebSocket messages and the protocol reorder buffer are bounded to 1 MiB each;
sequence windows are capped at 64 frames. Retransmission is bounded to five attempts
per pending protocol message with unchanged identity/sequence, not a new remote
command. The output queue applies backpressure. There is no infinite reconnect,
replacement session, or automatic command restart after uncertain delivery.
See [protocol references and limits](native-protocol.md).

These bounds do not mean every allocation or wall-clock operation is bounded.
The SDK decodes API responses before application inventory/document checks;
there is no application-wide HTTP response-body cap. Regular-file I/O may block
in the kernel despite cancellation. No process-wide memory quota is enforced.

## Target, document and remote privilege selection

The executable accepts EC2 IDs or exact Names. Every session resolves all EC2
pages, rejects duplicate Names even if only one is running, and requires running.
Only the validated unique ID reaches SSM and connection diagnostics. These reads
use the selected SDK identity without fallback and require ec2:DescribeInstances,
which cannot be scoped to an instance ARN. Exact-target readiness then checks
all SSM pages and requires one Online EC2 registration with validated metadata;
CLI shell/command setup also requires Linux. Unexpected/duplicate records or later
pagination failures never produce partial success. State/Online reads do not
prove future state or session authorization. Read-only EC2 discovery and exact-Name
resolution exist as libraries and read-only `--list`/JSON joining is implemented;
connection Name/state integration is implemented. EC2 pagination/metadata
errors discard all records; duplicate Names never select an arbitrary host.
Listing exposes only seven allowlisted fields after both inventories complete,
sanitizes human Names and escapes Unicode in wire JSON. Read-only clients cannot
start sessions; listing neither claims permission proof nor tests it through StartSession.

Read-only --check accepts IDs/exact Names, refuses ambiguity/stopped targets,
requires Linux/SSM Online and validates the default shell document/key region. It uses
only read APIs and reports untested session permissions/connectivity explicitly.
Only a classified STS metadata denial may be unavailable; authentication, malformed
metadata, cancellation and unknown failures remain fatal. Every subsequent API
keeps the same selected config, never original credentials after role failure.
No session start/termination, channel/listener, command or elevation tests access.

Shell preflight reads the authenticated default-version document and requires
known schema 1.0 Standard_Stream preferences and a literal supported KMS key or
no key. Only no-key shells can use handshake-free capability. Omitting
`--document` still leaves StartSession's document unset, preserving account
defaults. Only that owned, document-verified shell may become ready on its first
ordered output without a handshake. Commands always require their handshake.
Unverified KMS and encrypted forwarding are refused; document-owned KMS shells/commands
bind selected identity/key/owned IDs/random context and verify an encrypted
challenge. The client never disables KMS preferences or
substitutes a less restrictive document. TLS remains encrypted even in the supported
non-KMS mode; KMS shell/command encryption is an additional implemented layer with synthetic
TLS/SDK coverage, not live AWS proof.

Preflight does not pin the version used by StartSession. An authorized document
administrator can change the default between calls. Such administrators remain
trusted; preflight is not a defense against them. Logging, Run As, shell profiles
and server timeouts are not rewritten, and their effective enforcement depends
on AWS and the agent. Unknown/unsupported document behavior fails closed.

No automatic local or remote `sudo` is issued. This does **not** guarantee an
unprivileged remote shell: AWS documents that default `ssm-user` sessions can have
sudo permissions. Administrators must review effective OS privileges and may
configure Run As; AWS's Run As selection fails when the selected account is
unavailable rather than falling back to `ssm-user`.
See [AWS default user permissions](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-ssm-user-permissions.html)
and [AWS Run As behavior](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-preferences-run-as.html).

Remote command text is bounded and quoted as one remote `/bin/sh -c` argument.
It is intentionally interpreted by that remote shell, including metacharacters.
Compatible command documents must request no elevation and separate output with
unchanged command substitution. A user can still explicitly request privileged
commands if the remote OS permits them. Exit status is accepted only from the
typed protocol, not text printed to stdout, and requires validated completion and
successful cleanup. See [remote command boundaries](remote-commands.md).

The native library's explicit-destination Port setup verifies the authenticated
agent version and exact host/port properties before readiness. Remote properties
cannot choose a local bind address or a Unix socket path; terminal payloads and
ambiguous flags fail closed. Destination-error controls have no stream identity
and are not application bytes. ServeForward now owns a supplied matching loopback
listener, bounded socket workers and the Port channel, with joined cleanup,
ten-second transmission/delivery/write budgets and no payload logging. Local/peer
EOF uses full close, not a promised independent TCP half-close. Unscoped agent
destination errors stop the session. The forward package creates exact-port TCP4
loopback listeners without elevation or alternate-port retry; callers own cleanup
until serving takes ownership. Loopback is not local-user authentication.
ssm.StartForward creates owned sessions using only the two fixed AWS forwarding
documents and explicit destination parameters; it cannot authorize handshake-free
readiness. Exact authenticated Port negotiation is still required before traffic.
The development CLI wires owned AWS termination after local shutdown, with a
fresh ten-second best-effort budget. Setup reserves the port before authentication,
without accepting application traffic until validated readiness; local processes
may still connect to the OS backlog meanwhile. ConnectForward alone owns neither
AWS termination nor listener cleanup. The opt-in OS loopback listener test now
passes; live AWS remains unverified. See
[forwarding boundaries](native-forwarding.md).

## Terminal and audit visibility

Interactive output is not escaped or filtered: ANSI colors and full-screen programs
require raw terminal bytes. A hostile target can send deceptive text, terminal
control sequences or emulator-specific clipboard/title actions. The client is
not a terminal-output sanitizer or sandbox. Use a maintained terminal emulator,
review its remote-control features and avoid displaying untrusted captured output
as a safe diagnostic. Noninteractive command output is also raw stdout/stderr.

The application does not record terminal input/output as diagnostics. This is
not a promise that sessions are unrecorded: target shell history, applications,
terminal recording, redirects and AWS logging can retain secrets. AWS shell
session logging depends on configured preferences; audit its effective setup
separately. AWS documents that Session Manager payload logging is unavailable for
SSH-over-SSM and port-forwarding sessions. Ordinary shell sessions execute through
SSM; SSH-over-SSM tunnels a separate SSH protocol; forwarding tunnels application
TCP traffic. They are not interchangeable audit mechanisms.
See [AWS session logging limitations](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging.html).

This client implements native forwarding, not SSH or plugin compatibility, and
never falls back to them. No public listeners are supported. Do not infer forwarded
traffic visibility merely because ordinary shell logging is configured. Tunnel
TLS to AWS does not replace application-level authentication or TLS to the remote
service; other local users can access the bound loopback port.

## Shutdown and operational review

On controllable exit paths, channel workers stop before saved terminal settings
are restored and owned AWS cleanup is attempted with a fresh ten-second context.
Physical Ctrl+C/Ctrl+D in raw mode are remote bytes; external termination signals
cancel locally. The TTY-only line-start `~.` escape disconnects locally. Duration
limits are local and do not override server-side policy.

Only a session obtained from this process's successful StartSession response is
eligible for its cleanup. Failure is reported, not converted to success; the
ownership object permits retry but the CLI does not promise eventual cleanup.
Closing a WebSocket or restoring a terminal is not proof that TerminateSession
succeeded. SIGKILL, machine loss, failed credential refresh and connectivity loss
can prevent both restoration and cleanup. An invalid/missing response session ID
cannot be safely guessed. Authorized operators must inspect any remaining owned
session through their normal AWS procedures; never terminate unrelated sessions
to compensate for uncertain ownership.

Before production use, review least-privilege IAM/trust policy, actual remote OS
identity/privileges, effective documents/preferences/logging, credential cache
permissions, terminal/proxy trust, and cleanup under interruption. Complete live
interoperability and dependency/vulnerability review first. Existing offline
tests cover synthetic SDK authentication/refresh, ownership/cleanup, malformed
protocol input, TLS, redaction, PTYs/signals, bounded I/O and command status; they
are not evidence of live policy effectiveness or an independent security audit.
