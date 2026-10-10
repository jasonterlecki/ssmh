# Native forwarding: protocol work in progress

Forwarding is wired into the development CLI through `--forward` and
`--forward-host`; live AWS interoperability remains unverified. The explicitly
opted-in OS loopback listener test passes after user-enabled network access.
Native `NewProtocol` still rejects Port sessions without the explicit-destination
setup path. `ConnectForward` now
establishes an authenticated Port channel, and ServeForward now orchestrates
bounded socket workers on a matching caller-supplied loopback listener. The
forward package now creates validated loopback listeners and ssm.StartForward
creates fixed-document owned sessions; the CLI composes their lifecycle.
Forwarding requires the existing StartSession/TerminateSession
permissions for the approved forwarding target/document. No dependency is added.

## Verified transport layers

AWS's [Port plugin](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/plugins/port/port.go)
requires a SessionType handshake and selects multiplexing for
LocalPortForwarding when the client's advertised version supports it. This is
not a terminal shell or an unframed WebSocket stream. The
[official plugin's mux handler](https://github.com/aws/session-manager-plugin/blob/mainline/src/sessionmanagerplugin/session/portsession/muxportforwarding.go)
places smux bytes in SSM Output payloads; the
[agent's mux handler](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/plugins/port/port_mux.go)
passes those bytes to a smux server. An individual inner frame can cross SSM
message boundaries. Ordered SSM sequencing/deduplication must precede inner
decoding; SSM frame acknowledgement is not acknowledgement of TCP application
processing.

The reviewed upstream [smux frame definition](https://github.com/xtaci/smux/blob/v1.5.24/frame.go)
uses an eight-byte header: version byte, command byte, little-endian uint16 body
length and little-endian uint32 stream ID. Version 1 defines SYN/open=0,
FIN/close=1, PSH/data=2 and NOP=3. The
[default configuration](https://github.com/xtaci/smux/blob/v1.5.24/mux.go)
uses version 1; [session processing](https://github.com/xtaci/smux/blob/v1.5.24/session.go)
defines stream creation, close/data delivery and zero-ID NOP generation.
These links specify the reviewed wire format, not a claim that every AWS
installation uses that dependency release. No upstream library code is vendored.

## Implemented inner codec

`internal/transport/native/mux.go` provides package-private version-1 encoding
and incremental decoding. Encoding refuses payloads exceeding 65535 bytes before
the uint16 conversion. Decoding validates a complete header before allocating a
body and retains only one partial header/body, at most 8+65535 bytes. Each feed
is capped at the outer SSM codec's 1 MiB payload limit. A completed body transfers
to the consumer without aliasing the input chunk or a later frame. Consumers
must apply bounded backpressure rather than accumulate an unbounded result list.

Unknown versions/commands, version-2 update messages, nonempty control bodies,
zero IDs on stream frames and nonzero IDs on NOP fail closed. Empty data frames
are allowed, matching upstream receive behavior. Errors permanently fail the
decoder and release partial references; finishing a truncated header/body is
an error, never successful EOF. Valid frames before a later malformed frame may
already have been delivered: this is per-frame validation, not transactional
validation of a whole feed. Consumer errors are replaced with a fixed message
to avoid exposing application data or endpoints. Formatting redacts body data.
Releasing references does not promise Go-memory erasure.

Tests independently specify literal little-endian wire bytes and exercise every
split point, one-byte feeds, multiple frames, binary preservation, maximum size,
ownership/no-aliasing, malformed headers, all truncations, terminal failure,
error redaction and fuzz parsing. They test the codec, not stream ownership,
smux interoperability through an installed agent, a TCP listener or live AWS.

## Implemented client stream state

`mux_state.go` now drives the inner decoder with a private single-owner client
state. It issues monotonically increasing odd stream IDs starting at 3, matching
the reviewed [upstream client allocation](https://github.com/xtaci/smux/blob/v1.5.24/session.go),
and never wraps/reuses them. At most 64 streams can be locally active. A full
table refuses another open without consuming an ID; local close frees capacity
but subsequent connections receive fresh IDs. Encoded open/data/close frames
must be transmitted in order; the caller must shut down on unknown/failed
transmission, not retry a new open or replay data on another connection.

Outgoing data is copied and capped at the reviewed default 32768-byte smux frame
size. Receive callbacks transfer bytes only to an issued active local stream,
without a state-owned queue. Peer FIN generates one receive EOF; the local send
direction remains available until local close, consistent with upstream
[stream read/write/close behavior](https://github.com/xtaci/smux/blob/v1.5.24/stream.go).
Local close emits one FIN and removes both local directions. Duplicate peer FIN
is ignored. Data after peer EOF while the stream is still active fails closed.

Unsolicited peer opens, even IDs and never-issued IDs fail the entire state.
Data/FIN racing an already completed local close is discarded, as in upstream
smux. A monotonic issued-ID watermark identifies those retired streams without
an unbounded history; their bytes cannot reach a later connection. NOP and empty
data are consumed without application delivery; no keepalive response is generated.
Callbacks must apply bounded backpressure and must not re-enter the state machine.

Malformed input or consumer failure permanently releases state. Completion
requires a complete inner frame and no remaining local streams; it does not
independently validate outer SSM completion or convert a disconnect to EOF.
Shutdown is idempotent and drops references without network I/O or FIN replay.
No sockets, workers, listeners or AWS sessions are owned by this state machine:
their shutdown/cleanup and coordinated cancellation are still caller integration
responsibilities, now supplied by ServeForward for the native channel and local
connections/listener. AWS session ownership remains outside serving. Formatting
and consumer errors do not expose forwarded data.

Tests cover interleaved streams, exact SYN/PSH/FIN wire bytes, binary preservation,
fragmentation, peer/local close ordering, late-close races, ID exhaustion,
capacity/chunk bounds, peer violations, incomplete completion, shutdown,
redaction and fuzz input. These are offline state/codec tests, not a working
tunnel or a test against an installed smux/AWS agent.

## Implemented Port channel negotiation

`ConnectForward` takes an owned session and independently validates an explicit
forwarding target. It uses the existing TLS/SigV4/token connection, ordered
protocol loop, setup deadline and cancellation behavior. It does not start or
terminate AWS sessions, bind a listener, or forward local socket traffic.

The authenticated handshake must specify Port and TCP LocalPortForwarding, with
exact requested remote/local ports and host (absent/empty for instance-local
forwarding). Unique, recognized string properties only are accepted. A nonempty
Unix socket, different connection type, altered host/port, unknown field,
duplicate field, malformed version or KMS action is refused. No remote property
can choose a local address or create a file. Remote-host DNS resolution remains
agent-owned; the client neither resolves nor silently substitutes the hostname.

Agents must advertise a canonical four-part numeric version strictly greater
than 3.1.1511.0. This follows the official plugin's
[capability comparison](https://github.com/aws/session-manager-plugin/blob/1.2.814.0/src/version/versionvalidator.go)
and [keepalive threshold](https://github.com/aws/session-manager-plugin/blob/1.2.814.0/src/config/config.go),
also excluding older agents requiring the basic stream or mux keepalives.
All native session paths advertise fixed wire compatibility level `1.2.339.0` in both
OpenDataChannel and handshake response. This is not the ssmh release version or
a claim that the official plugin is running. The reviewed agent's
[selection and keepalive comparisons](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/plugins/port/port.go)
select mux and disable agent-generated mux keepalives for this level.
Shell/command paths share this numeric level for output-separation compatibility;
it does not relax Port's explicit-destination or agent-capability requirements.

Only binary Output and the exact four-byte big-endian destination-failure Flag=3
are accepted after readiness; resize/stdout-stderr/exit-status semantics are not
forwarding semantics. The Flag remains a separate ordered control: AWS sends no
stream ID with it, so the client must not guess which connection failed. Input
is bounded binary Output or the exact terminate Flag=2. That flag alone is not
proof of remote termination; owned AWS cleanup remains caller responsibility.

Offline tests cover exact and malicious properties, agent-version boundaries,
pre-readiness refusal, terminal/flag isolation, sequence deduplication and fuzz
input. Actual TLS/HTTP tests with a synthetic agent verify signed upgrades,
token and version exchange, unchanged binary bytes, ordered controls and owned
EOF for both destination modes. Invalid setup is rejected before network I/O;
terminated sessions cannot be reused. No installed AWS agent, forwarding document
selection, smux peer or local TCP tunnel is tested by these channel fixtures.

## Implemented socket serving

`ServeForward` requires an established explicit-destination native Port channel
and a supplied TCP listener reporting exactly the requested `127.0.0.1` port.
Non-Port/not-ready/ended/already-owned channels and other addresses are rejected
without taking resource ownership. Validation transfers the listener and channel
once; the caller must not continue accepting, sending or receiving on them.
The function owns accepted connections and joins all its workers before returning,
but it never starts or terminates an AWS session or creates a listener.
Loopback is not per-user authentication: other local processes can connect, so a
sensitive remote service should not be forwarded on an untrusted shared machine.

At most 64 active/pending connections are accepted, with a slot reserved before
Accept so backlog pressure stays outside application memory. Each connection has
one reader and one writer; one owner drives all mux state and serializes SYN/PSH/FIN.
Outgoing frames are split into contiguous 1024-byte SSM chunks. Data/accept
admission pauses at 64 queued frames, reserving 64 additional FIN slots. Each local
reader retains at most one 32768-byte packet while blocked by admission. Per-client
output queues hold four inner frames (each at most 65535 bytes) plus one in-flight
write. One outer input and the existing channel/reorder queues are independently
bounded; these are not a process-wide memory quota.

An inner-frame transmission, one outer-frame delivery wait, and each local write
have ten-second budgets. Delivery uses bounded backpressure rather than dropping
frames. smux v1 has no per-stream receive-credit mechanism here; one slow local
reader can temporarily block others, and an expired budget fails the whole
session. The single serialized writer interleaves bounded frames, never replays
an open or application data on another stream after uncertain delivery. No mux
keepalives, terminal transformations, stdin processing or payload diagnostics occur.

Local read EOF closes the full local connection and queues one FIN after previously
accepted input. Peer FIN first drains queued remote output to the local socket,
then closes the full local connection and sends FIN. This follows the reviewed
[agent copy-and-close behavior](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/plugins/port/port_mux.go);
it does not promise an independent TCP half-close or delivery of traffic racing
an already completed local close. Socket errors, protocol failures and the agent's
unscoped destination-error flag terminate serving visibly, rather than guessing a
failed stream or continuing with uncertain delivery.

Cancellation/failure closes the owned listener and local sockets, joins their
workers, then closes/joins the channel and driver goroutines. Cleanup failures
remain errors, with no raw endpoint/payload-bearing causes displayed. Only exact
local channel shutdown cancellation leaves are filtered; independent joined
failures and caller cancellation remain. Owned outer EOF is successful only with
complete inner framing, no open local stream and completed queued transmissions.
AWS TerminateSession remains separately caller-owned and best effort.

Tests use `net.Pipe`, synthetic listener/channel boundaries and a real native SSM
channel fixture. They cover concurrent streams, binary bytes, large batched
transfers and bounded backpressure, retired IDs, capacity, blocked I/O cancellation,
full close after output, malformed/control/IO/deadline failures, cleanup errors and
capability/loopback gating. The real channel fixture verifies outer acknowledgements
and active-stream retransmission suppression before socket delivery. TLS and token
authentication are tested separately in ConnectForward fixtures. No OS TCP bind,
installed smux/SSM Agent or live AWS interoperability is claimed.

## Owned forwarding session creation

`ssm.StartForward` selects exactly `AWS-StartPortForwardingSession` for an empty
host or `AWS-StartPortForwardingSessionToRemoteHost` for an explicit host. These
are the documents and singleton string-list parameters documented in
[AWS's forwarding instructions](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#sessions-remote-port-forwarding).
Both port numbers are explicit canonical decimal strings; host is sent unchanged
only for the remote-host mode, without local DNS resolution or bracket insertion.
Instance ID, region, reason and exported target fields are validated before AWS.
No user-selected document, port default, shell, SSH or Run Command is substituted.

This calls the existing Start ownership boundary with the caller's selected SDK
client and context. It returns no usable session on API/authentication failure;
malformed transport material with a safe returned ID triggers fresh bounded
best-effort cleanup. A successful response racing with cancellation retains
ownership so the caller can terminate it. The helper never creates a listener,
connects a channel or alters IAM/agent configuration. The returned session does
not authorize handshake-free operation.

Unlike shell/command setup, this helper does not read account-owned preferences:
it selects only the two fixed AWS-managed forwarding documents. The caller must
then use ConnectForward's authenticated strict Port/property/KMS validation before
serving any application traffic. No additional GetDocument permission is needed
by this helper. Tests cover structured requests, both modes, IPv6/host fidelity,
invalid setup, canceled requests, redacted failures and owned cleanup. Actual SDK
signing/serialization/decoding/termination are tested against synthetic HTTP,
not a live service. The CLI invokes this helper only for validated forwarding.

## Loopback listener creation

`internal/forward.Listen` validates the complete destination again and uses
`net.ListenConfig.Listen` with `tcp4` and exactly `127.0.0.1:LOCAL_PORT`. It does
not resolve the remote hostname locally. Port conflicts and permission failures
produce fixed diagnostics; it never chooses another port or elevates privileges.
It checks the returned address and closes partial/error or canceled setup
results, reporting independent close errors without raw network causes.

The context bounds creation only. After successful return the caller owns the
listener until closing it or transferring it to ServeForward; cancellation of
the setup context does not close it. Nothing is accepted before serving. No AWS
session is created by this listener helper. Loopback
is not per-user authentication: other local users/processes may connect.

Default tests use a private bind boundary to verify exact arguments, invalid
target refusal, conflict/error classification, cancellation, returned-address
gates and cleanup/ownership. Real loopback bind/conflict/accept testing is opt-in:
`SSMH_TEST_TCP=1 go test ./internal/forward -run TestListenRealTCP`.
The test now passes real bind/conflict/accept checks after user-enabled network
access; neither default
tests nor this optional OS test prove live AWS interoperability.

## CLI lifecycle and remaining validation

CLI setup validates forwarding options and reserves the exact loopback port before
authentication; conflicts do not create AWS sessions. It then loads the selected
SDK credentials/role, resolves one exact EC2 ID/Name, requires running, checks
complete Linux/Online SSM registration, starts the
fixed-document owned session and connects a strict explicit-destination Port
channel. One setup deadline covers binding through handshake. Optional duration
starts after StartSession, including channel setup, not initial authentication.
Only the resolved ID reaches SSM. Duplicate Names fail even with stopped matches.
State/Online reports are not future-state or permission proof; EC2 read access
is required for explicit IDs as well as Names.

Normal stderr displays the instance and, after readiness, listening address and
destination. These writes use private bounded descriptors even without verbose;
quiet suppresses informational output. Forwarding leaves stdout/stdin untouched,
uses no terminal raw mode/escape processing and stops on executable signal
cancellation (including Ctrl+C). Verbose/debug use the existing selected-identity,
SDK metrics and native state diagnostics. MFA callbacks are disabled before
serving and during cleanup, never silently re-enabled on refresh.

A once-only listener owner joins setup/serving cleanup. Setup errors close every
returned local resource; serving joins workers/channel, and listener closure
precedes fresh ten-second best-effort owned AWS termination. Only process-created
sessions are terminated. No shell/plugin fallback, port/identity substitution or
application payload logging occurs. No custom --document is accepted in forwarding.

CLI tests compose both modes with synthetic SDK/channel/listener boundaries,
verify exact parameters, identity/option preservation, no terminal use, diagnostic
separation, setup/duration/cancellation/cleanup and post-setup MFA refusal. A real
native adapter rejection test verifies true-nil channel handling and fresh AWS
cleanup without network access. Lower-layer real TLS/protocol/net.Pipe tests are
separate; these do not prove a live end-to-end tunnel. Before release, verify
both forwarding documents through explicitly opted-in live AWS
sessions, including IAM policies, the installed agent and destination services.

The current native shell/command paths are unchanged. See
[native protocol](native-protocol.md) and [security boundaries](security.md).
