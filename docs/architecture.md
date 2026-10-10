# Architecture and current implementation

This describes the source as implemented, not the complete requested product.
The repository map is [CODEX.md](../CODEX.md); engineering/security requirements
are [AGENTS.md](../AGENTS.md). Live AWS interoperability has not been verified.
Native shells, noninteractive commands and forwarding by EC2 ID or exact Name are
wired into the development executable. Read-only EC2/SSM listing and JSON output
and default-shell prerequisite checks are implemented. All sessions require one
exact EC2 target and running state. Plugin launch and KMS forwarding remain
incomplete; native KMS shells/commands have synthetic TLS/SDK coverage, not live proof.

## Composition and ownership

```text
main.go or cmd/ssmh -> app: signal cancellation, final reporting and process exit
    -> cli: parsing, validation, operation selection and orchestration
        -> aws: SDK provider chain / selected identity / explicit AssumeRole
        -> ec2: complete exact ID/Name resolution / running-state validation
        -> ssm: complete Online registration check / owned StartSession
        -> native: authenticated TLS WebSocket / validated ordered protocol
            -> terminal.Run, command.Run or native.ServeForward
        -> fresh-context owned TerminateSession after local shutdown
```

CLI `connect.go` shares identity, setup/lifetime deadlines, MFA disablement,
diagnostics and AWS cleanup across the three implemented operations. Both
executable entry points delegate to the same app.Execute; plain root `go build`
and the conventional cmd path have no independent lifecycle logic. Lower-level
packages do not parse CLI arguments. Native transport uses configuration DTOs
for forwarding expectations, not CLI or terminal code. Terminal/command packages
consume authenticated native message types through small channel interfaces.
The separate `forward` package binds the loopback listener; native serving owns
accepted sockets and multiplexing, not AWS session control.

`ssm.Session` ownership is private and can only come from a successful StartSession
response with a validated ID. Transport material is a deliberately explicit
secret-bearing interface, not a diagnostic DTO. A malformed response with a safe
returned ID causes bounded best-effort cleanup; an invalid ID cannot safely be
guessed or terminated. Successful termination is idempotent and releases token/URL
references; failure remains retryable. This is not memory erasure or guaranteed
cleanup after lost connectivity/SIGKILL. See [security](security.md).

## Operation-specific boundaries

Shell setup reads the selected/default document and requires schema 1.0
Standard_Stream with recognized preferences and a literal supported key or no
KMS selection. Only the latter grants handshake-free capability. It preserves
account logging, run-as, profile and timeout settings. Only this owned verified
shell may become ready on the first ordered Output without a handshake; silent
shells can time out. Handshake-required/KMS sessions cannot use that exception.

Command setup serializes a bounded command as one quoted remote `/bin/sh -c`
argument; there is no local shell execution or implicit Run Command. Authenticated
document preflight requires non-elevated NonInteractiveCommands with separate
output. Result status is known only after one valid typed exit payload, owned EOF,
successful output delivery and cleanup. Text cannot impersonate exit status.
Authorized document administrators remain trusted: StartSession cannot pin the
default version read by preflight. See [commands](remote-commands.md).

Forwarding reserves exactly `127.0.0.1:LOCAL_PORT` using TCP4 before authentication,
without accepting application traffic during setup. It starts one of the two
fixed AWS forwarding documents with explicit host/port parameters and verifies
the authenticated Port handshake against the unchanged destination. No custom
document, public binding, local DNS resolution or fallback is allowed. Once ready,
ServeForward owns listener/channel/connections and bounded smux v1 workers. Local
and peer EOF use full close, not independent end-to-end TCP half-close. An agent
destination error has no stream identity and stops the whole tunnel. Loopback
does not authenticate local users. See [forwarding](native-forwarding.md).

## Authentication, transport and diagnostics

StartCommand retains a literal document-selected KMS key only after validating
non-elevation/separate-output policy and the selected region/partition. Its owned
NonInteractiveCommands capability cannot authorize a shell or handshake-free
readiness. Native Connect uses the same selected SDK config and verifies the
encrypted challenge; decrypted stdout/stderr/typed status enter the existing
result receiver and owned cleanup path. Live AWS proof remains pending.

AWS configuration/provider refresh use the pinned SDK v2. Explicit AssumeRole
failure never falls back to the original identity. MFA uses a no-echo controlling
terminal during setup only; prompting is disabled before serving and owned cleanup.
Later refresh that needs a prompt fails closed rather than consuming remote input.
SDK-managed SSO cache updates are distinct from application credential storage.
See [authentication](authentication.md) and [IAM prerequisites](iam-policy.md).

Custom CA/profile selection uses the SDK builder with guards installed before
resolution. Builder copies refuse redirects and unsupported signed endpoints,
respect proxies and disable keepalives; the returned application client owns a
guarded pool. Native WebSockets inherit the selected roots/proxies, verify TLS
and upgrade before token submission, and never disable certificate validation.
Protocol and inner mux processing bound lengths, buffering, streams and retries;
unexpected messages fail closed. These local bounds do not bound SDK HTTP-body
decoding or configuration-file reads. See [protocol](native-protocol.md).

Default diagnostics are minimal stderr; verbose/debug opt into validated identity
and fixed provider/lifecycle summaries. Debug records bounded API/transport events
without SDK objects, signed URLs, tokens or application payloads. Forwarding's
default address report also uses private bounded stderr writes. Terminal/command
stdout/stderr are intentional raw remote output, not sanitized diagnostics.
Broken writers cannot skip owned cleanup. See [diagnostics](diagnostics.md).

## Tests and unfinished boundaries

Unit tests use synthetic service responses/credentials and in-memory transports;
TLS tests actually verify certificates, but not live AWS. Terminal tests use
controlled Linux PTYs. Native streaming/forwarding tests compose outer framing,
acknowledgements, inner mux state and net.Pipe socket workers. Real OS TCP binding
is explicitly opt-in and now passes after user-enabled network access. ARM64 builds
are cross-compilation evidence, not ARM64 runtime tests.

Read-only EC2 discovery/exact-Name resolution and SSM Inventory are implemented,
and used for list/check/JSON routing and all connection target/state checks.
Only the uniquely resolved ID reaches SSM; duplicate Names cannot select an
eligible host by discarding stopped matches. Listing uses separate read-only client interfaces,
complete inventories and exact-ID joins; it defaults to running/Online. Names
are sanitized for human output; ASCII JSON preserves exact decoded Unicode.

Check reads STS metadata (explicit denial is labeled unavailable without changing
credentials), resolves an ID/exact Name, requires running/Linux/Online and shares
the read-only default shell-document validator with StartShell. It starts no
session or channel. Its report distinguishes prerequisites from untested session
authorization/connectivity; private stdout/stderr/MFA/HTTP ownership mirrors listing.
SSM Online alone never proves EC2 running state or StartSession permission.
EC2 uses the pinned SDK v2 client; user-enabled network access resolved the earlier
module-download restriction. No handcrafted AWS client is substituted.

Plugin executable inspection, owned-response preparation and selected-provider
credential response encoding exist only as libraries. Safe launch still requires
identity/refresh, logging/output and lifecycle controls; no child session is
launched by the CLI. Document-owned KMS shells/commands use selected-config key preparation
and encrypted challenge; unverified/forwarding KMS is refused. See
[discovery](discovery.md) and [plugin status](plugin-backend.md).
