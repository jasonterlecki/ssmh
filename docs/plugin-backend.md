# Official plugin compatibility: implementation status

Session launch through the plugin is not implemented yet. `--backend plugin`
still fails before authentication, and `auto` still selects native only. A
successful executable probe is not a working compatibility backend, authenticated
channel or permission check.

## Implemented preflight

`internal/transport/plugin.Inspect` finds `session-manager-plugin` on PATH and
executes its structured `--version` argument without a local shell. Installation
and PATH must be trusted. Relative PATH entries/current-directory discovery,
nonregular/nonexecutable files, set-ID executables and group/world-writable
executables are refused. Symlinks to an eligible executable are accepted; parent
directory ownership and binary provenance are not verified. Changes between
inspection and a future launch are not prevented.

The child receives no caller environment or stdin: only `LANG=C` and `LC_ALL=C`.
In particular the probe does not inherit AWS credentials, SSM response variables,
proxy configuration, shared profile selectors or dynamic-loader variables. This
does not sandbox a malicious executable; it already runs as the caller and can
access that user's files. A trusted program may also initialize its own logging
when asked for its version. No plugin settings are modified by the client.

The probe is capped at three seconds or the caller's earlier deadline. Stdout is
limited to a 64-byte fixed buffer, stderr is discarded, and neither stream nor
raw subprocess errors enter diagnostics. Output must be a canonical four-part
ASCII numeric version, optionally followed by LF/CRLF. Each component fits in
16 bits; prefixes, spaces, controls, extra lines and oversized output fail closed.
Successful exit and a validated version of at least **1.2.764.0** are required.
The executable handle keeps its path private and redacts formatted output.

AWS's [installation guidance](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
and [version history](https://docs.aws.amazon.com/systems-manager/latest/userguide/plugin-version-history.html)
currently specify 1.2.764.0 as the minimum supported version. The floor is a
reviewed compatibility prerequisite, not a guarantee that every later version is
secure or supports every client operation. Administrators should review and
maintain their installed version. Nothing is downloaded or installed automatically.

Probe timeout kills and reaps the directly launched process. Pipe draining has
an additional 250ms bound if a descendant holds an inherited pipe open; this
does not guarantee termination of descendants launched by a malicious program.
Preflight itself performs no AWS request, token handoff or terminal activation.
Offline tests use the test executable as a synthetic plugin and exercise real
process execution, environment isolation, malformed/oversized output, failed
exit, deadlines, missing/relative paths and version parsing. They do not validate
an installed official plugin or its network behavior.

## Implemented response-handoff primitive

`handoff.go` now prepares an in-memory response from a live, process-owned
`ssm.Session`. Nil/zero/terminated sessions are refused. Only SessionId, StreamUrl
and TokenValue are serialized with their official JSON field names. Invalid UTF-8
is refused rather than replaced in authentication material. JSON escaping preserves
quotes, Unicode and controls; NUL bytes cannot enter an environment entry. Encoded
entries are capped at 120 KiB, below Linux's per-string limit on a 4 KiB page system;
the [kernel defines that limit as 32 pages](https://github.com/torvalds/linux/blob/master/include/uapi/linux/binfmts.h).
Oversized encoding fails without including the response in an error.

The package-private primitive adds one named response entry to an explicitly
supplied child environment and removes all older response-prefix aliases. It
never inherits or mutates the process-global environment. Base environments are
limited to 256 entries, each at most 120 KiB, with a 256 KiB retained-byte budget
including the response. Missing keys/separators and NUL-containing entries fail
closed. These are handoff bounds, not a complete OS launch/argument budget or
credential/environment allowlist; those policies remain launch-layer work.

Formatting the handoff object redacts all response material. Clearing it releases
its own reference, not copied environments or Go string memory. Session termination
prevents new preparation but cannot revoke a response copied earlier: the future
launch layer must coordinate session/handoff lifetimes and clear unused copies.
No credentials are retrieved, terminal activated, or official plugin session run.

Tests launch a synthetic child with the same verified name/lookup/unset/SDK JSON
decode convention. They verify exact token preservation, absence of response
material from argv, alias replacement, no mutation of the supplied environment,
redacted formatting, release/ownership refusal and encoded/environment bounds.
They do not prove official plugin interoperability, TLS or credential behavior.

## Implemented selected-provider credential response

`credentials.go` adapts the parent's already selected SDK provider/cache to the
official credential-endpoint JSON format. Every request calls that same provider;
the adapter never reloads a profile, searches for a different identity or falls
back after failure. This retains the selected provider's SDK refresh path rather
than installing a static credential snapshot in the child's environment.

Only AccessKeyId, SecretAccessKey, Token and (when CanExpire is true) Expiration
are encoded. Expiration remains the provider's time, normalized to UTC, without
extending credential validity. Nonexpiring credentials omit it. Refreshable
long-lived keys without an STS token are allowed, matching the SDK's endpoint
provider distinction between expiration and token presence. Account/provider
metadata is not serialized.

Key, secret and token fields must be bounded printable ASCII (128/4096/65536 bytes,
with an optional empty token). Missing keys, controls/non-ASCII, expired/invalid
expiration, raw retrieval failures, cancellation and encoded responses above
120 KiB return no bytes. Errors never retain or display raw provider causes.
Cancellation is checked before and after retrieval; this adapter relies on the
SDK provider honoring context and does not add a goroutine or independent timeout.

The returned bytes contain credentials: they belong exclusively on an
authenticated credential transport, never argv, application output, logs or disk.
The adapter opens no endpoint, listener or files and supplies no child credential
environment. The relay below now supplies local transport. Isolating the child's
provider chain and maintaining refresh across an actual plugin process are still
required before backend enablement.
Do not treat this codec as a running credential server or a security boundary.

Offline tests use the actual SDK v2 endpoint provider with a synthetic HTTP
client: GET/authorization/JSON decoding, a selected parent SDK cache and its
invalidation/refresh path, static versus expiring fields, redaction and cancellation.
They do not test a network listener, automatic timed expiration, the installed
plugin or live AWS. The [pinned SDK endpoint provider implementation](https://github.com/aws/aws-sdk-go-v2/blob/credentials/v1.19.18/credentials/endpointcreds/provider.go)
defines the JSON/expiration format; AWS's [container credential-provider guide](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
documents endpoint GET and authorization settings. No additional AWS permissions
or resources are created by the adapter.

## Implemented authenticated loopback credential relay

`credential_server.go` implements a package-private local HTTP server, not an
enabled backend. It binds an ephemeral TCP4 port on `127.0.0.1` only and creates a
cryptographically random 256-bit authorization value. Every accepted credential
request uses the parent's exact selected provider/cache. No profile lookup,
alternate identity, credential file, global environment mutation or AWS resource
creation occurs in the relay.

Only origin-form GET `/credentials` with the exact literal loopback authority and
one matching Authorization header is accepted. Alternate hosts, escaped paths,
queries, bodies and duplicate authorization are rejected before provider access.
Responses disable caching; failures contain fixed JSON, never provider errors or
partial credentials. HTTP error logging is discarded and handle formatting omits
both endpoint and token.

The server admits at most eight accepted sockets and two simultaneous provider
retrievals. Keepalives are disabled; header/read/write budgets are 2/5/6 seconds,
the configured HTTP header limit is 4096 bytes (Go's parser has its own bounded
read-ahead), and each retrieval context is capped at five seconds. Shutdown
cancels request contexts, closes sockets and waits for admitted handlers. A
shutdown deadline reports incomplete work rather than claiming success. SDK cache
internals may suppress refresh cancellation and outlive the canceled caller;
joining handlers does not mean all SDK-owned work has stopped. A provider ignoring
context can also prevent complete shutdown.

This uses the SDK's supported HTTP loopback credential-endpoint protocol; it is
not an insecure AWS API endpoint or permission to downgrade AWS TLS. The endpoint
authorization token is supplied only through two private child environment
settings, never a URL/argument/file. The future launcher must prevent proxying of
this local credential traffic without bypassing proxies for AWS, isolate all
alternative credential/configuration sources, and coordinate process lifetime.
Those two settings alone do not implement these controls. Loopback plus a token
is not isolation against the same local user, privileged local software or OS
inspection of a child environment. No application credentials are persisted.

Successful close releases relay references; its owned JSON byte buffer is cleared
after writing. Go strings, HTTP buffers, SDK/provider state and copied child
environments are not guaranteed erased. Copied credentials retain their normal
AWS validity after relay shutdown.

Offline handler tests compose the actual SDK decoder and selected cache refresh,
exercise request/authentication rejection, bounded retrieval and cancellation.
`SSMH_TEST_TCP=1` additionally exercises real loopback requests, refusal without
authorization and listener closure, using synthetic credentials only. These tests
do not validate the installed official plugin or live AWS. `--backend plugin`
remains refused and native sessions open no credential relay.

## Implemented explicit child credential environment

`environment.go` builds a private child environment from the selected region,
live relay, and explicitly supplied noncredential settings. It never reads or
appends `os.Environ`. Credentials, profile selectors, role/web-identity settings,
ECS relative URIs, endpoint authorization files, service endpoint overrides,
dynamic-loader variables and plugin configure bypasses cannot be supplied.
Unknown settings and duplicates fail with fixed errors, without echoing values.

Both SDK shared-file paths are `/dev/null`, IMDS is disabled, region is explicit,
and defaults/retry mode are standard with three attempts. Only the relay's full
URI and generated authorization token supply child credentials. The future
launcher must also pass an empty profile argument: an original or assumed-role
profile must never be passed back to the child SDK loader.

Selected PATH, TERM, LANG/LC_ALL, upper/lowercase HTTP/HTTPS proxy and NO_PROXY,
AWS_CA_BUNDLE, SSL_CERT_FILE and SSL_CERT_DIR settings can be supplied explicitly.
Values are bounded to 4096 bytes with no controls/invalid UTF-8; at most sixteen
settings of at most 4160 bytes per entry are accepted. PATH/CA paths must be
absolute, PATH/directory lists have
at most 32 entries and no empty components, and TERM is a bounded simple ASCII
name. Proxy/CA values are not printed; no NO_PROXY exception or TLS bypass is
added. Parent resolved CA/proxy settings must be faithfully transferred by the
future launcher, not guessed from the original profile or a new environment.
Programmatic CA readers and profile-relative paths need an explicit supported
mapping before launch; this builder does not invent one.

The reviewed official [Unix shell implementation](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/src/sessionmanagerplugin/session/shellsession/shellsession_unix.go)
invokes `stty` by name for terminal setup/restoration. This compatibility backend
therefore also needs a trusted terminal helper on its explicitly supplied PATH.
The builder requires absolute PATH entries but does not inspect the helper or
parent directories. Those launch checks remain pending; native ssmh invokes no
stty process and has no such dependency. Installed versions must be reviewed.

The private handle redacts formatting, returns copied entries and releases its
retained references on clear. New copies are refused after relay cancellation/
shutdown; already copied environments cannot be revoked. This is not erasure of
copied strings/process
environments. Owned StartSession response assembly remains separate. No child
session, terminal mutation, AWS call or credential file is created by the builder.

Actual synthetic subprocess tests resolve SDK LoadDefaultConfig, retrieve through
the endpoint provider and invalidate the child cache before a second retrieval.
They demonstrate that parent environment keys/profile selectors are not inherited,
and an endpoint failure returns no fallback credentials.
Offline tests intercept the endpoint provider's own HTTP client (the generic SDK
HTTP-client option does not configure it). Opted-in loopback subprocess tests use
its normal client and verify both parent-provider retrievals with HTTP/HTTPS proxy
settings unchanged. This tests the pinned SDK chain, not installed-plugin signing,
automatic expiry refresh, reconnects, logging or effective parent CA fidelity.

## Verified upstream launch constraints

The following findings come from a review of AWS's `mainline` source on
2026-10-09, not execution of an installed plugin. They are version-dependent;
the minimum-version probe does not certify these properties in a local binary.
The re-check identified commit
[`7cde6748cc6cffbc69546b4de08e603cd39be6d8`](https://github.com/aws/session-manager-plugin/commit/7cde6748cc6cffbc69546b4de08e603cd39be6d8)
as the reviewed mainline snapshot. No executable was installed or run for this
source review; Linux logging and selected-credential launch gates remain unresolved.

### Independent logging and mixed output

The [session entry point](https://github.com/aws/session-manager-plugin/blob/mainline/src/sessionmanagerplugin/session/session.go)
initializes its logger before dispatching `--version`. On Linux,
[log configuration discovery](https://github.com/aws/session-manager-plugin/blob/mainline/src/log/log_unix.go)
reads `/usr/local/sessionmanagerplugin/seelog.xml`, independent of the child
environment and working directory. The [built-in configuration](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/src/log/defaultconfig.go)
has root logging off but includes an error-level test-file exception and file
outputs. It is not an unconditional no-logging/no-file-effects policy. An installed
configuration can enable logging and the logger watches for changes. Stripping environment variables
or choosing a private working directory therefore does not disable plugin logs.

The [channel handler](https://github.com/aws/session-manager-plugin/blob/mainline/src/sessionmanagerplugin/session/sessionhandler.go)
passes the stream URL to an error-level reconnect log. The session entry point
also prints raw startup errors to its output writer; normal startup writes
its session banner to stdout. A future launcher must establish a logging policy
that remains effective for the child's lifetime and handle diagnostic output
without treating it as remote command output. Parent-side redaction alone
cannot protect independent log files, and a raw child pipe mixes information
that cannot safely be classified using text matching. `Inspect` supplies no
authentication material, but it is not a guarantee of zero filesystem effects.
Do not edit the administrator's installed logging configuration automatically.

### Implemented read-only logging prerequisite

`logging_linux.go` now checks the fixed installed configuration without changing
it. Root-owned directories from `/` through the installation and a root-owned
regular config are required, with no group/world write permissions, symlinks or
set-ID modes. A nonblocking NOFOLLOW open and before/after file identity check
refuse leaf substitution and special files. The read is capped at 1025 bytes;
configurations larger than 1024 bytes fail closed.

Only `<seelog type="sync" minlevel="off"/>` (or its paired-tag equivalent, with
XML whitespace and either attribute order) is accepted. Exceptions, outputs,
additional attributes, namespaces, comments, declarations and directives are
refused. This intentionally narrow grammar avoids treating a root off setting
as proof about exceptions or opening configured output files. AWS's
[pinned vendored parser](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/vendor/src/github.com/cihub/seelog/cfg_parser.go)
supports the accepted attributes and optional omitted outputs/exceptions;
[level selection](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/vendor/src/github.com/cihub/seelog/cfg_logconfig.go)
lets exceptions override root constraints. No new dependency is added.

This private check is not yet wired to a launcher or CLI. It neither locks the
file nor constrains root administrators, who remain trusted to keep logging
disabled for the entire child lifetime. Initial cancellation and a final context
check do not interrupt a stalled filesystem syscall. Read/parse/close errors use
fixed messages without file contents or OS causes. Missing/unreadable settings
are refused rather than relying on the plugin's built-in fallback. Unit/fuzz-seed
tests cover grammar, bounds, synthetic ownership/modes and real local symlink/
non-root refusal, not an installed plugin's successful initialization or reload.
Version/provenance, process and mixed-output gates still prevent backend enablement.

### Separate credential loads and reconnect behavior

The [SDK configuration helper](https://github.com/aws/session-manager-plugin/blob/mainline/src/sdkutil/awsconfig.go)
calls `config.LoadDefaultConfig` using the region/profile passed to the plugin.
The channel handler separately loads credentials for initial non-presigned
WebSocket signing, session resume and termination. Initial signing obtains a
credential value; resume attempts retrieve another value and update the socket.
The parent's selected provider is not inherited merely because StartSession
used it. Passing an original profile after explicit AssumeRole can therefore
select a different identity and is not an acceptable handoff.

The reviewed handler uses background contexts for these operations, and some
configuration/credential failures are logged before channel setup continues.
A future launcher must supply only the selected-provider refresh mechanism,
prevent alternate credential/configuration sources, bound child lifetime and
verify failure behavior. It must not enable `SSM_PLUGIN_SKIP_CLIENT_CONFIGURE`
as a workaround for authentication failure. Resume may replace the stream URL;
initial parent validation alone does not verify a subsequent URL. Reconnect
endpoint validation, signing and replay behavior still require review/testing
against the actual supported executable. The credential-response adapter does
not resolve these process-level constraints.

The [native KMS review](native-protocol.md#kms-stream-encryption-and-remaining-gates)
also compares this plugin snapshot against agent commit
`f397c74d46f99d78244a2bcb469bb86729672ff9`. That agent can require a random
KMS-context challenge acknowledgement which the reviewed plugin's handshake
structures do not supply. Do not weaken the agent's requirement to make fallback
work. Installed-version policy compatibility must be verified separately; this
source comparison is not a statement about all plugin releases or local settings.

The snapshot adds a
[stream-URL validator](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/src/sessionmanagerplugin/session/session.go)
on initial setup. The
[resume handler](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/src/sessionmanagerplugin/session/sessionhandler.go)
still copies a replacement StreamUrl into the channel without calling that
validator. The initial check is an upstream
improvement, not equivalence to this client's boundary: it accepts `ws` as well
as `wss`, multiple service/region host shapes and extra environment-supplied hosts,
rather than requiring the exact selected regional TLS-only endpoint. An installed
version cannot be assumed to contain the snapshot. Initial parent validation
does not enforce the same rule inside later child reconnects. No insecure scheme,
extra-host environment override or authentication-failure workaround is enabled
by ssmh. This review does not justify enabling fallback.

## Remaining launch security work

Before enabling the backend, implement and verify all of the following:

- SDK v2 StartSession and process-owned cleanup, including launch failure and
  cancellation. Do not delegate ownership decisions to raw plugin exit status.
- Integration of the response-handoff primitive without tokens/signed URLs in
  command arguments or disk files. AWS added environment-variable handoff in
  1.2.536.0; the
  [official argument parser](https://github.com/aws/session-manager-plugin/blob/mainline/src/sessionmanagerplugin/session/session.go)
  reads a named `AWS_SSM_START_SESSION_RESPONSE...` variable and unsets it.
  This still exposes the initial child environment to permitted local process
  inspection, so it is not a secret-isolation boundary against the local user/OS.
- Selected-identity propagation without falling back to another credential
  chain or profile. Version/signing/KMS/refresh behavior must be checked against
  the installed official implementation rather than inferred from a version.
- Terminal ownership/restoration, signal delivery, bounded shutdown, and safe
  stdout/stderr separation. The official plugin emits its own session messages;
  no reliable remote command exit status is promised here.
- Review of plugin logging, endpoint/proxy/TLS behavior, reconnect/replay and
  permission requirements. Application redaction does not control independent
  plugin logs or raw child output.
- Loopback-only binding and validated destinations for forwarding, using the
  official Port session mechanism, never an interactive shell as a TCP stream.

These are pending implementation gates, not guarantees supplied by Inspect.
See [security assumptions](security.md) and [native transport limits](native-protocol.md).
