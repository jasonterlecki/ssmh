# Native Session Manager transport

The native transport is in progress and integrated into the initial shell CLI.
Live AWS interoperability is not verified. The codec and state machine are independent implementations based on
AWS's official [message definitions](https://github.com/aws/session-manager-plugin/blob/mainline/src/message/clientmessage.go)
and [serialization implementation](https://github.com/aws/session-manager-plugin/blob/mainline/src/message/messageparser.go).

Binary SSM frames contain a 120-byte fixed prefix. The header-length value is
116; the following four-byte payload length completes the prefix. Integers use
big-endian encoding. A 16-byte UUID is serialized with its low 64 bits before
its high 64 bits; acknowledgement JSON uses the canonical UUID string. The
payload digest is SHA-256. The codec bounds payloads to 1 MiB and validates
schema, exact lengths, known types, sequence range, flags, and digest before
exposing payloads. Publication notifications can contain a zero digest only
when their payload is empty, consistent with the AWS implementation's special
handling of those notifications.

All native paths use fixed numeric wire compatibility level `1.2.339.0` in
OpenDataChannel and handshake responses, independently of ssmh's release/build
version. This is not a claim that the official plugin is running or that every
plugin feature is implemented. The reviewed
[agent data channel](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/datachannel/datachannel.go)
uses numeric client-version comparisons around separate command stdout/stderr
support (documented first version `1.2.312.0`); a development label is not a
suitable capability advertisement. This replaces the previous `ssmh-dev` wire
value. Forwarding already used the same numeric level to select mux without
agent keepalives. Unsupported KMS/actions and mismatched session types remain
refused, regardless of the advertised version. Tests assert literal versions in
all shell/command handshakes, authenticated TLS token exchange and handshake-free
shell setup; forwarding fixtures check both advertisements. No live agent
interoperability is asserted by those tests.

Protocol processing follows AWS's
[data-channel state handling](https://github.com/aws/session-manager-plugin/blob/mainline/src/datachannel/streaming.go)
and [handshake structures](https://github.com/aws/session-manager-plugin/blob/mainline/src/message/handshakemessage.go).
Unknown actions and unverified/unsupported KMS requests fail closed;
the client must never downgrade to an unencrypted application data stream.

## KMS stream encryption and remaining gates

Document-owned KMS shells/commands are supported through StartShell/StartCommand and native Connect,
with synthetic TLS/SDK verification, not live AWS proof. Unverified KMS actions,
Port encryption and parameterized keys remain refused. No plugin fallback
or preference/policy changes occur. KMS permission must already be authorized.

The source review pins agent commit
[`f397c74d46f99d78244a2bcb469bb86729672ff9`](https://github.com/aws/amazon-ssm-agent/commit/f397c74d46f99d78244a2bcb469bb86729672ff9).
Its [crypto implementation](https://github.com/aws/amazon-ssm-agent/blob/f397c74d46f99d78244a2bcb469bb86729672ff9/agent/session/crypto/blockcipher.go)
adds a base64-encoded 16-byte random challenge to the KMS request handshake.
When acknowledged, that value belongs in the KMS encryption context as
`aws:ssm:RandomChallenge`, alongside the owned session and target IDs. This is
distinct from the subsequent encrypted data-channel challenge. Its
[data-channel handler](https://github.com/aws/amazon-ssm-agent/blob/f397c74d46f99d78244a2bcb469bb86729672ff9/agent/session/datachannel/datachannel.go)
can require `ChallengeAcknowledgement`; omission fails when the agent's
`RequireKMSChallengeResponse` setting is enabled. Do not disable that setting or
acknowledge a challenge that was not actually bound into the KMS request.

The reviewed plugin commit
[`7cde6748cc6cffbc69546b4de08e603cd39be6d8`](https://github.com/aws/session-manager-plugin/commit/7cde6748cc6cffbc69546b4de08e603cd39be6d8)
still lacks these fields in its
[handshake structures](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/src/message/handshakemessage.go).
It cannot satisfy the agent's required random-context acknowledgement as written.
This is a comparison of pinned source snapshots, not a finding about every
installed/future plugin or a claim that the agent setting is enabled locally.
A minimum version number alone is not evidence of KMS-policy compatibility.

AWS's [plugin key service](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/src/encryption/kmsservice.go)
requests 64 data-key bytes. The
[directional ciphers](https://github.com/aws/session-manager-plugin/blob/7cde6748cc6cffbc69546b4de08e603cd39be6d8/src/encryption/encrypter.go)
split them into two AES-256 keys, one per direction, with a 12-byte nonce prefix
and GCM authentication tag. The native implementation retains the
already selected SDK identity/region/network policy, validates the selected key
and handshake, binds the owned IDs and supplied context challenge, bounds the API
call, validates key/ciphertext sizes, and completes the encrypted challenge before
readiness. Original encrypted frames must remain immutable for retransmission;
plaintext, keys and raw errors must never enter diagnostics or disk. No KMS
SDK dependency or encryption capability is introduced by this source review.

Protocol and authenticated TLS tests now cover legacy and random-context KMS
requests, including the document-authorized no-handshake shell path. They assert
unsupported action status, ordered ACK/refusal response, no false key/challenge
acknowledgement, no reflected request material and permanent refusal of later
completion, challenge or plaintext. These are refusal tests, not KMS
interoperability evidence.

### Implemented private encrypted-payload codec

`encryption.go` now implements a single-owner in-memory AES-256 GCM codec, not
an operational KMS session by itself. Connect composes it only for StartShell/StartCommand's
document-owned encryption capability. Exactly
64 bytes produce agent-to-client decryption and client-to-agent encryption states
in AWS's half-key order. Identical halves are rejected as an additional reflection
defense, not a new wire requirement. The caller retains ownership of the input
key buffer and must clear it; constructor state does not retain that buffer.

Go's [NewGCMWithRandomNonce](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce)
supplies the compatible 12-byte nonce prefix and 16-byte tag. Each client key
allows at most 2^32 encryptions. Wire payloads, including the 28-byte overhead,
must fit the existing 1 MiB bound. Empty authenticated plaintext is allowed at
the codec level; the future handshake/operation layer must enforce its own
payload semantics. No additional authenticated data is supplied, matching the
reviewed AWS format rather than inventing framing authentication.

Invalid lengths, inactive state, exhausted quota and authentication failures
return no bytes, use fixed errors and deactivate both directions. Pointer/value
formatting redacts data. Returned bytes do not alias inputs. Clearing releases
key-schedule references, not guaranteed erasure of Go/crypto memory or returned
plaintext/ciphertext. This codec alone does not enforce sequencing, replay
suppression, document/key/context fidelity or channel readiness.

Tests independently compose AWS's nonce-prefix format with standard GCM and
verify a fixed vector from [Go's AES-256 tests](https://github.com/golang/go/blob/go1.27.2/src/crypto/cipher/gcm_test.go).
They cover both directions, reflection rejection, every corrupted nonce/data/tag
byte, exact/oversized bounds, key-buffer clearing, quota, fresh nonces and fuzzing.
All keys are synthetic; no SDK call, credential loading, disk key material,
preferences change or live KMS proof is introduced by codec tests. The document/
Connect integration uses selected-identity key preparation for owned shells/commands.

### Private encrypted protocol integration

The package-private constructor now takes an explicitly selected key and a
one-shot preparer. Handshake fields cannot enable it in ordinary Connect. All
actions must validate before the callback: exact session type, one KMS action,
exact selected key, optional canonical 16-byte base64 context challenge and no
unknown actions. Invalid/failed preparation or missing/oversized key ciphertext
fails closed and discards partial cipher state. The SDK adapter binds
owned session/target IDs and the supplied challenge before returning successfully;
only then may the response claim ChallengeAcknowledgement.

The pinned agent sends a 64-byte encrypted challenge. The client decrypts it
using the agent-direction key, encrypts the same bytes using the client-direction
key and replies before accepting ordered HandshakeComplete. Input/readiness and
application data remain unavailable until then. Output, StdErr and typed ExitCode
decrypt after sequence validation; outgoing Output encrypts once. Resize and
handshake/control payloads are not additionally encrypted. Replay fingerprints
retain original ciphertext; retransmissions reuse the same nonce/ciphertext,
UUID and sequence without a new encryption. Encryption-required policy survives
key release, so cleanup cannot revive a plaintext path. Errors, owned close,
retry exhaustion and channel shutdown release key/preparer references.

Synthetic tests exercise independent agent-direction authentication, legacy and
random-context responses, invalid actions before preparation, partial-provider
failure redaction, challenge/readiness ordering, application ordering, replay,
retransmission, an in-memory encrypted channel exchange, joined key release on
cancellation/disconnect/owned EOF/authentication failure, bounded retry exhaustion
and release-without-downgrade. Parameter parsing also has a fuzz target. They
make no KMS API call. The
preparer is synchronous: the SDK call honors setup cancellation and its request budget;
returned ACKs are written after preparation, not before the callback.
Selected-document ownership and Connect integration compose this path;
live encrypted AWS interoperability remains unverified.

### Private SDK key preparation

`kms.go` uses pinned SDK v2 KMS v1.53.0 with selected configuration, never a new
credential chain. Owned session/target/region metadata must match the SDK region.
Endpoint overrides are rejected and SDK payload logging is disabled. Key IDs,
multi-region IDs and aliases are preserved; ARN references must match owned
region/partition. Returned key ARN must match an explicit key or selected alias's
account. Alias resolution trusts signed KMS responses and authorized admins.

The one-use callback requests NumberOfBytes=64 with owned IDs and optional exact
random challenge. Its five-second context honors parent cancellation. Plaintext
must be exactly 64 bytes and encrypted key blob 1–6144 bytes, with no recipient
ciphertext. Errors, cancellation or ended ownership discard results. SDK plaintext
is cleared on every response path, without guaranteed SDK/Go/crypto memory erasure;
returned ciphertext is copied independently. Mock and actual signed SDK synthetic
HTTP tests check context, identity, encoding, bounds, clearing and fixed failures.
No actual KMS call/billing occurs in these tests. Connect supplies StartShell/StartCommand's
authenticated key capability and its setup/lifetime context. Context fields are
non-secret and may appear in AWS audit logs; see
[GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html).

## Ordered stream and transport

The state machine requires the explicitly selected shell/command session type,
validates each acknowledgement against the sent UUID and sequence, and suppresses
duplicate output. Sequence windows are 64 frames; queued out-of-order payloads
total at most 1 MiB. Input uses the official plugin's 1024-byte chunks.
Retransmission reuses the original UUID and sequence, is capped at five retries,
and never restarts a command or session. Old/conflicting replays and unsupported
actions fail the channel. Session closure must identify the owned session and
have no pending out-of-order output; a sequence gap cannot produce normal EOF.

Control JSON must be valid UTF-8 and one object, with no duplicate keys (including
escaped equivalents or case variants) anywhere inside it. Handshakes,
acknowledgements, channel-close messages and local resize input share this check;
ambiguous remote messages permanently fail the protocol. Limits are 64 KiB,
16 nested containers, 64 keys per object and 256 bytes per decoded key, with the
smaller acknowledgement/completion/close/resize limits still enforced. Unknown
unique fields remain allowed for compatibility. Parser errors do not expose
payloads. These are local defensive limits, not claimed AWS protocol limits.

The WebSocket implementation uses Go's standard HTTP/TLS transport and
[RFC 6455](https://www.rfc-editor.org/rfc/rfc6455). It inherits the configured AWS
client's certificate roots and proxy behavior, validates the HTTP/1.1 upgrade
response, applies client masking, bounds reassembled messages and fragment count, and
supports interleaved ping/pong frames. It negotiates no compression, extensions,
or subprotocols. SigV4 signs the upgrade unless AWS provided a presigned URL.
The session token is submitted only after TLS and upgrade validation. API
response-body timeouts are removed for the long-lived upgraded connection;
connection establishment and individual writes remain bounded. Keepalive pings
occur each minute, and three minutes without a received frame ends the socket.

`Channel` owns one socket reader and one protocol event loop, joins both on
shutdown, and bounds its output queue to eight messages. Slow consumers apply
backpressure. Cancellation of a submitted input closes the channel to prevent
ambiguous delivery from being retried in a new session. Only a validated owned
channel-close message produces normal EOF. Transport loss and local cancellation
remain distinct errors; they are not remote exit status.

The terminal shell loop sends resize payloads using `cols`/`rows`, following
AWS's [SizeData definition](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/contracts/model.go).
It chunks input at 1024 bytes, preserves raw control bytes, routes stdout/stderr,
and shuts down the channel before restoring local terminal state. External
signals cancel locally; raw-mode keyboard Ctrl+C is remote input. No terminal
stream is copied into diagnostics. AWS session cleanup remains caller-owned.

The [command result receiver](remote-commands.md) consumes typed
stdout/stderr/exit-code payloads from NonInteractiveCommands channels. It requires
one canonical AWS exit-status payload and owned-close EOF before exposing a known
result. It is wired to CLI command mode with document preflight and remote shell
serialization. Stream output is never scanned for status.

Tests use in-memory connections for actual TLS and HTTP upgrades without needing
OS listeners. Tests exercise framing and the
complete synthetic agent handshake/stream, but do not prove live AWS
interoperability. KMS shells have additional synthetic coverage. A separate
[forwarding channel/codec](native-forwarding.md) implements explicit-destination
Port negotiation. The native library now also serves bounded multiplexed socket workers
on a caller-supplied matching loopback listener; the forward package now creates
validated TCP4 loopback listeners; AWS/CLI orchestration is implemented, while
live AWS interoperability remains unverified.
Port input/output are binary, not terminal data; only validated Port
destination-error controls are delivered separately from application bytes.
The current agent's [Standard_Stream plugin](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/plugins/standardstream/standardstream.go)
skips handshakes when no KMS encryption is configured, as selected by the
[session plugin wrapper](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/plugins/sessionplugin/sessionplugin.go).
The official client's [ProcessFirstMessage](https://github.com/aws/session-manager-plugin/blob/mainline/src/sessionmanagerplugin/session/sessionhandler.go)
selects shell on initial Output. Here this is allowed only for an owned shell
whose authenticated GetDocument preflight verifies literal absent/empty KMS and
Standard_Stream; no timeout-driven downgrade exists. First output is validated,
ordered, acknowledged and retained for delivery. TLS/token authentication is
unchanged. Unverified KMS actions, unexpected later negotiation and commands
without handshakes fail closed. Default preferences are read from
SSM-SessionManagerRunShell without changing StartSession's omitted DocumentName;
missing/unreadable preferences fail closed. Document administrators remain
trusted: AWS StartSession cannot pin the read default version. A silent shell
profile may still time out before readiness. See AWS's
[preferences document](https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-create-preferences-cli.html)
and [Session schema](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-schema.html).
CustomerMessage is excluded from
command stdout; its diagnostic presentation remains to be implemented.

The protocol payload is intentional raw remote output. It must not be copied to
diagnostic logs. Wire identifiers, frame offsets, and numeric payload assignments
are interoperability requirements, not invented behavior. Tests use synthetic
data and independently specified wire bytes, never real authentication payloads.
