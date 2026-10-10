# Remote commands (development build)

`--command`/`-c` selects native noninteractive execution on a Linux EC2 instance.
The CLI validates the selected document before starting a session, submits a
quoted command parameter, negotiates NonInteractiveCommands and owns cleanup.
`internal/command.Run` receives output from an
already authenticated, verified `NonInteractiveCommands` channel; it does not
create sessions, select documents or send command text. The caller owns AWS
session termination. Live AWS interoperability has not been tested.

The receiver forwards typed stdout and stderr to their respective local streams,
without reading stdin, using raw mode, sending resize/control bytes, recording
transcripts or executing local processes. It preserves the bytes supplied by
the transport; this is not a guarantee that SSM Agent preserves all arbitrary
binary output. Pipe/TTY writes are cancellable. Regular-file writes can still
block inside the kernel.

## Exit status

AWS's [shell plugin implementation](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/shell/shell.go)
sends status using the `ExitCode` payload type after draining separate stdout and
stderr. The receiver requires its exact ASCII `EXIT_CODE: N` format, where `N`
is a canonical decimal integer from 0 through 255. A negative agent status
(including `-1` for signal termination) is unknown, not a fabricated signal code.
Ordinary output containing this text is never treated as status.

`Result.ExitCode()` reports whether status is known. The zero value is unknown;
a known nonzero remote status is not itself a transport failure. Status becomes
known only after exactly one valid typed status, the native channel's validated
owned-session close, complete local output delivery and successful local cleanup.
Missing, duplicate, malformed or unavailable status, output after status,
disconnect, cancellation or local failure invalidates the entire result. The
receiver closes its channel on every return. It never treats socket EOF as
successful command completion or retries a command.

The agent's separate-output mode is required to obtain this typed status. A
command document using combined output may close without a status and therefore
cannot be reported as successful by this receiver. See the AWS
[session schema](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-schema.html)
and agent [shell configuration](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/contracts/model.go).

## Document and command boundary

The CLI reads the selected document's default version through `ssm:GetDocument`.
It requires an active JSON Session document with schema 1.0,
NonInteractiveCommands type, a String `command` parameter, exact Linux command
placeholder `{{ command }}`, explicit `runAsElevated: false`,
`separateOutputStream: true` and empty output prefixes. Unknown fields, duplicate
keys (including case variants), excessive nesting and oversized content are
rejected. Root, parameter-definition and Linux property names must match exactly;
case-variant names and null/non-string output prefixes fail before StartSession.
Canceled preflight fails even if the document API returns a valid response.
Document inputs are left unchanged; the server remains authoritative
for Session Manager preferences. Present inputs must use recognized exact names;
literal supported `kmsKeyId` values enable native command encryption. Null,
unknown/parameterized keys and cross-region/partition ARNs fail before StartSession.
StartCommand binds the key to the owned NonInteractiveCommands session; ordinary
Start and shell capabilities cannot authorize it. The selected SDK configuration
generates the key with owned session/target/random context, and the encrypted
challenge must complete before readiness. Stdout, stderr and typed exit status
are authenticated/decrypted before the existing result receiver sees them.
Caller `kms:GenerateDataKey` and target `kms:Decrypt` permissions/key policy must
already allow the selected key; no permissions are changed. Synthetic TLS/SDK/CLI
tests cover this path; live AWS interoperability remains unverified.

This follows the pinned agent's
[shared session handshake](https://github.com/aws/amazon-ssm-agent/blob/f397c74d46f99d78244a2bcb469bb86729672ff9/agent/session/plugins/sessionplugin/sessionplugin.go)
and [encryption of Output/StdErr/ExitCode](https://github.com/aws/amazon-ssm-agent/blob/f397c74d46f99d78244a2bcb469bb86729672ff9/agent/session/datachannel/datachannel.go).

The default command document is `AWS-StartNonInteractiveCommand`, but this is
not an assurance that its regional definition meets these requirements. If it
requests elevation or combined output, it is refused before execution. Use
`--document` to select an administrator-reviewed compatible document. No document
is created, modified or silently substituted by the client. `ssm:GetDocument`
can be scoped to the selected document ARN, alongside StartSession and owned
TerminateSession permissions. Document names and supported SSM ARNs are accepted.

A minimal document shape for administrator review is:

```json
{
  "schemaVersion": "1.0",
  "sessionType": "NonInteractiveCommands",
  "parameters": {"command": {"type": "String", "maxChars": 32768}},
  "properties": {
    "linux": {
      "commands": "{{ command }}",
      "runAsElevated": false,
      "separateOutputStream": true
    }
  }
}
```

This is not a policy-complete deployment template. Administrators must apply
their logging, Run As, duration and other session preferences and review the
document and IAM permissions before registration. The client does not request
root, sudo, a different remote user or changes to instance settings.

The Linux agent's
[command executor](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/session/shell/shell_unix.go)
tokenizes noninteractive command arguments instead of automatically interpreting
shell metacharacters. Passing arbitrary shell text directly would change its
meaning. `SerializeShell` encodes `/bin/sh -c` plus one POSIX-quoted argument;
the argument is the original command text. Quotes, newlines, shell operators and
Unicode are preserved for the remote shell to interpret. This serialization is
never evaluated locally. The encoded parameter, including quoting expansion,
is capped at 32 KiB. NUL, invalid UTF-8 and oversized commands fail validation.
Remote stdin is not forwarded; commands requiring input should use shell mode.

The agent supplies no command properties in its session-type handshake. Document
administrators therefore remain trusted: StartSession has no version-pinning
field, and a concurrent change of the default document after GetDocument cannot
be excluded. Prevent unauthorized document modification through IAM. Preflight
is not a guarantee against a malicious authorized administrator or compromised
remote instance.

The CLI returns the verified remote status only after local output/channel and
AWS owned-session cleanup succeed. A nonzero status has a static diagnostic that
does not contain command text. Authentication, setup, disconnect or missing status
returns a local failure, not a guessed remote status. Local cancellation maps to
130, invalid invocation to 2 and other local failures to 1; a cleanup failure
overrides propagation of a received remote status and is reported separately.

Synthetic tests cover all allowed status values, malformed and unavailable
statuses, separate raw output, stdout status impersonation, duplicate status,
output after status, premature disconnect, local broken pipes, blocked-output
cancellation and channel-close failures. They require no live credentials.
Additional tests cover serialization round trips, document rejection, CLI
document/parameter preservation and cleanup failure overriding remote status.
