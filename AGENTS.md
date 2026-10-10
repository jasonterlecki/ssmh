
# AGENTS.md
# ssmh - Engineering and Security Instructions

## 1. Project Overview

`ssmh` is a Linux command-line application written in Go that provides SSH-like remote access to Amazon EC2 instances using AWS Systems Manager (SSM) Session Manager.

It uses AWS IAM authentication and SSM transport rather than the SSH protocol.

Primary objectives:

1. Security and correctness.
2. Reliable AWS authentication and authorization.
3. Safe and predictable session management.
4. Robust Linux terminal handling.
5. Maintainable, testable Go code.
6. Minimal dependencies and deployment complexity.

Security takes precedence over functionality, performance, compatibility, and convenience.

Never compromise security to make a feature work.

---

## 2. Agent Responsibilities

Any AI coding agent working on this repository MUST:

- Read `AGENTS.md` before making changes.
- Read `CODEX.md` before exploring or modifying project files.
- Follow existing architectural conventions.
- Inspect relevant source code before editing.
- Understand security implications before implementing changes.
- Prefer incremental, verifiable changes.
- Preserve existing working functionality.
- Add tests for meaningful behavior changes.
- Update documentation alongside implementation.
- Treat `CODEX.md` synchronization as an inseparable, mandatory part of every development task.
- Report security-relevant changes and unresolved risks.

Never assume existing code is secure simply because it compiles or passes tests.

Never silently weaken security controls.

If instructions conflict, follow this priority:

1. Applicable higher-priority instructions and safety constraints.
2. Security requirements in this document.
3. Project architecture and documented invariants.
4. Explicit task requirements.
5. Existing implementation conventions.

Raise conflicts rather than silently bypassing them.

---

## 3. Mandatory CODEX.md Synchronization

`CODEX.md` is the mandatory, continuously maintained repository map and
architectural reference for this project. Every coding agent MUST automatically
update `CODEX.md` whenever repository structure, file responsibilities,
interfaces, architectural relationships, security boundaries, or implementation
status changes.

Maintaining `CODEX.md` is an inseparable part of every development task. No
explicit user request is required.

Before declaring a task complete, the agent MUST verify that `CODEX.md`
accurately reflects all relevant changes.

A development task is not complete until `CODEX.md` synchronization has been
verified.

This requirement applies to all future development activities, including bug
fixes, refactoring, feature development, security hardening, dependency
changes, and repository restructuring.

It MUST be created if missing.

The actual source code is the source of truth for implemented behavior.
Investigate and resolve any contradiction between it and `CODEX.md`; never
knowingly leave the map inaccurate or outdated.

### Purpose

`CODEX.md` documents:

- Repository directory structure.
- Important files and their responsibilities.
- Go packages and their relationships.
- Major interfaces and exported components.
- AWS integration boundaries.
- Authentication and credential-handling components.
- SSM session lifecycle implementation.
- Native transport and compatibility backends.
- Security-sensitive components.
- Testing structure.
- Build and release configuration.
- Important architectural decisions.
- Known limitations and unfinished capabilities.

### Required Behavior

Before making changes:

1. Read `AGENTS.md` and `CODEX.md` before modifying relevant code.
2. Use `CODEX.md` to identify relevant components, file responsibilities,
   dependencies, architectural relationships, and security boundaries.
3. Verify the relevant descriptions against the actual source.
4. Inspect the actual code before editing.

During development, update `CODEX.md` as soon as a change affects the map; do
not defer synchronization until the end of a large effort. In particular:

1. Update entries whenever files are created, deleted, moved, or renamed.
2. Update entries for components whose purpose, behavior, responsibility, or
   interfaces change.
3. Update package dependencies and architectural relationships.
4. Review and update the security-boundary map whenever security-sensitive code
   changes, including authentication, AWS credentials, STS role assumption, SSM
   sessions, transport protocols, terminal handling, logging, or port forwarding.
5. Update implementation status when planned functionality becomes implemented.
6. Remove obsolete references and correct inaccurate descriptions.
7. Never include credentials, tokens, secrets, or sensitive authentication
   payloads in `CODEX.md`.

Before declaring a development task complete:

1. Inspect the files changed during the task and compare them with `CODEX.md`.
2. Update every affected section and confirm existing file references and
   descriptions are accurate.
3. Confirm planned files are not described as implemented.
4. Confirm security boundaries and architectural relationships remain accurate.
5. Record completion only after this synchronization verification succeeds.

Do not leave `CODEX.md` outdated.

### Initial Repository

If `CODEX.md` does not exist, create it before substantial implementation work.

If the project has not yet been initialized, document its actual current state.

Do not invent files, packages, or directories and describe them as existing.

Planned components may be documented separately, but MUST be clearly marked as planned.

### Maintenance Rules

- Keep entries concise and accurate.
- Organize by component and directory.
- Explain why important files exist.
- Identify security-sensitive files.
- Avoid duplicating full source code.
- Do not include secrets or credentials.
- Distinguish implemented functionality from planned functionality.
- Update the map in the same change as the associated source changes.
- Do not rewrite unaffected sections or create documentation churn for changes
  that do not affect the repository map, architecture, security boundaries, or
  implementation status.

`CODEX.md` is a living repository map, not a development diary.

---

## 4. Security Principles

All development MUST follow these principles:

### Least Privilege

Use the minimum permissions necessary.

Never require broad administrator permissions when narrower IAM permissions suffice.

Avoid wildcard IAM permissions unless technically necessary and explicitly documented.

### Secure by Default

The default behavior must be the safest practical behavior.

Insecure functionality must never be enabled implicitly.

### Fail Closed

When authentication, authorization, certificate validation, session validation, or protocol integrity cannot be established, refuse the operation.

Never downgrade to an insecure transport.

### Defense in Depth

Do not rely on a single mechanism to protect sensitive operations.

Validate input, protect credentials, enforce authorization through AWS, and handle session lifecycles safely.

### Minimize Attack Surface

Prefer fewer dependencies, fewer exposed interfaces, and fewer privileges.

Do not introduce unnecessary network listeners, subprocesses, or operating-system integrations.

### No Hidden Behavior

Security-sensitive operations must be explicit and auditable.

Never silently switch AWS identities, regions, accounts, instances, or transport modes.

---

## 5. AWS Credential Security

AWS authentication is a critical security boundary.

### Mandatory Requirements

- Use AWS SDK for Go v2 credential providers.
- Respect the standard AWS credential provider chain.
- Support AWS shared profiles and IAM Identity Center.
- Use STS AssumeRole for explicitly requested role assumption.
- Use temporary credentials wherever supported.
- Preserve SDK credential refresh behavior.
- Never hardcode credentials.
- Never write credentials to application configuration files.
- Never persist STS temporary credentials.
- Never print credential secrets.
- Never expose SSM session tokens.
- Never include sensitive tokens in error messages.
- Never transmit credentials to unauthorized endpoints.

Sensitive values include:

- AWS access key secrets.
- AWS session tokens.
- SSM session tokens.
- Authorization headers.
- Signed authentication payloads.
- MFA tokens.
- Credential-process responses.
- WebSocket authentication material.

### Credential Logging

Debug logging MUST NOT reveal credentials or secrets.

Do not dump complete AWS SDK requests, HTTP headers, environment variables, or credential objects.

Redact sensitive fields before logging.

Prefer allowlisted diagnostic fields over logging entire objects.

### AWS Identity

When useful, display non-secret identity information such as:

- AWS account ID.
- Selected region.
- Configured profile.
- Assumed role ARN.

Do not assume `sts:GetCallerIdentity` succeeding proves permission to start a session.

---

## 6. IAM Role Assumption

The `--arn` option allows the user to assume an explicitly specified IAM role.

Requirements:

- Use STS AssumeRole through AWS SDK v2.
- Respect AWS authorization decisions.
- Never attempt privilege escalation.
- Never search automatically for more privileged roles.
- Never silently substitute another role.
- Never fall back to original credentials after an explicitly requested AssumeRole fails.
- Do not persist assumed-role credentials.
- Use SDK-managed credential refresh where supported.
- Keep MFA handling secure.

Do not include MFA tokens or session credentials in command diagnostics.

If AssumeRole fails, terminate the operation with an actionable error.

---

## 7. SSM Session Security

Session Manager is the application's primary remote-access mechanism.

### Required Behavior

- Use authenticated AWS SSM APIs.
- Validate the selected region and target instance.
- Establish encrypted transport connections.
- Verify TLS certificates.
- Validate protocol messages.
- Respect AWS IAM permissions.
- Respect applicable Session Manager policies and configuration.
- Track ownership of sessions started by this process.
- Terminate owned sessions when appropriate.
- Clean up after recoverable failures.

### Prohibited Behavior

Never:

- Disable TLS certificate verification.
- Ignore session authentication failures.
- Reuse another user's session token.
- Log session tokens.
- Expose authenticated session URLs.
- Fall back silently to SSH.
- Open port 22 automatically.
- Install an SSH daemon.
- Modify EC2 security groups to enable connectivity.
- Alter instance IAM policies automatically.
- Change SSM Agent configuration without explicit authorization.

### Session Ownership

Only terminate sessions created and owned by the current process.

Use correct lifecycle tracking to prevent accidental termination of unrelated sessions.

Best-effort cleanup must never be represented as guaranteed cleanup.

---

## 8. Native Session Manager Protocol

The native Go transport implementation is security-critical.

AWS SDK v2 does not itself implement the complete interactive Session Manager data channel.

The implementation must follow verified protocol behavior.

Requirements:

- Use authenticated secure WebSockets.
- Validate expected protocol message types.
- Validate message lengths.
- Bound incoming message sizes.
- Validate framing and payload lengths.
- Validate sequence and acknowledgement data.
- Prevent unbounded memory allocation.
- Handle malformed messages safely.
- Handle unexpected disconnects.
- Avoid panics from untrusted network input.
- Avoid infinite reconnect loops.
- Avoid unsafe message replay.

Do not invent protocol behavior.

Consult official AWS documentation and available official implementations when necessary.

Treat remote protocol messages as untrusted input.

Do not disable validation to accommodate malformed messages.

Any newly implemented transport behavior MUST have tests for malformed or unexpected inputs.

---

## 9. Shell and Command Execution Security

`ssmh` provides remote shell access, which makes command execution particularly sensitive.

### Local Execution

Do not execute user-provided remote commands through a local shell.

Avoid:

    sh -c <user-input>
    bash -c <user-input>

Use structured process execution only when an external program is genuinely required.

Never concatenate untrusted strings into local shell commands.

### Remote Execution

Remote commands must be sent through the intended SSM session mechanism.

Preserve command arguments and quoting semantics.

Do not alter user commands silently.

Clearly document when a remote shell interprets a command string.

Do not silently use SSM Run Command as an alternative mechanism.

### Privileges

Never automatically run remote commands as root.

Do not automatically invoke `sudo`.

Do not attempt to bypass remote operating-system permissions.

The remote user and privileges are determined by the applicable SSM session configuration.

---

## 10. Terminal Security

Terminal input and output can contain sensitive information.

Requirements:

- Do not log interactive terminal input.
- Do not record passwords entered into remote sessions.
- Do not capture terminal output without an explicit feature requirement.
- Restore terminal settings after session exit.
- Handle signals safely.
- Prevent terminal state corruption.
- Avoid leaking terminal buffers.
- Handle binary and unusual terminal input safely.

Use established terminal libraries where practical.

Ctrl+C handling must distinguish between interrupting the remote shell and terminating the local client.

Terminal restoration must be attempted on all controllable exit paths.

Do not claim restoration is guaranteed after SIGKILL or abrupt process termination.

---

## 11. Port Forwarding Security

Port forwarding exposes a network service through the local machine.

It MUST be secure by default.

### Default Binding

Local forwarding must bind to:

    127.0.0.1

Do not listen on all interfaces by default.

Do not use:

    0.0.0.0

unless explicitly requested through a deliberately implemented and documented feature.

### Validation

Validate:

- Local port range.
- Remote port range.
- Destination hostname.
- Destination address syntax.
- Listener ownership.
- Port availability.

Reject malformed arguments.

### Restrictions

- Do not silently create public listeners.
- Do not enable privileged local ports through privilege escalation.
- Do not modify firewall rules.
- Do not modify security groups.
- Do not assume remote services are trusted.
- Do not log forwarded application payloads.

If non-loopback binding is ever implemented, require an explicit option and warn about its security implications.

Do not weaken defaults to make port forwarding easier.

---

## 12. Input Validation

Treat all external data as untrusted.

This includes:

- CLI arguments.
- Environment variables.
- AWS API responses.
- EC2 Name tags.
- EC2 instance IDs.
- IAM role ARNs.
- SSM session IDs.
- SSM document names.
- WebSocket messages.
- Remote hostnames.
- JSON input.
- Configuration files.

Requirements:

- Validate format where appropriate.
- Enforce reasonable size limits.
- Avoid unsafe parsing.
- Avoid path traversal.
- Avoid uncontrolled memory allocation.
- Avoid integer overflow.
- Avoid unsafe string interpolation.
- Avoid unexpected file creation or overwrites.

Never assume AWS metadata fields contain safe terminal text.

Escape or sanitize untrusted data when displaying it outside an intentional raw remote terminal stream.

---

## 13. Network Security

All AWS communication must use secure, authenticated endpoints.

Requirements:

- TLS verification enabled.
- No insecure HTTP fallbacks.
- No hardcoded proxy bypasses.
- Respect supported AWS SDK proxy configuration.
- Apply reasonable connection timeouts.
- Bound retries and backoff.
- Respect context cancellation.
- Close idle connections where appropriate.
- Avoid leaking connection resources.

Never disable certificate validation to troubleshoot connectivity.

If a connection fails due to certificate validation, report the problem rather than bypassing security.

---

## 14. Dependency and Supply Chain Security

Dependencies introduce security risk.

Rules:

- Prefer the Go standard library.
- Use maintained third-party libraries.
- Avoid unnecessary dependencies.
- Avoid abandoned or unexplained packages.
- Pin dependencies through `go.mod` and `go.sum`.
- Do not use arbitrary forked security-sensitive libraries without review.
- Do not download and execute unverified scripts.
- Do not fetch executable code from unknown sources during runtime.
- Do not embed secret material in build artifacts.

Review dependencies before adding them.

Use Go tooling where available:

    go mod verify
    go vet ./...
    go test ./...

Use `govulncheck` when available or as part of the security validation workflow.

Keep dependencies reasonably current.

Never blindly apply dependency upgrades without running tests.

---

## 15. Secrets and Sensitive Files

Never commit or intentionally store:

- AWS credential files.
- Private keys.
- Session tokens.
- MFA tokens.
- Passwords.
- Credential dumps.
- Sensitive debug logs.
- Temporary authentication payloads.

Do not generate files containing sensitive material unless explicitly necessary.

If temporary sensitive files are unavoidable:

- Use restricted permissions.
- Avoid predictable filenames.
- Delete them when no longer needed.
- Document their lifecycle.

Never add credentials to test fixtures.

Use synthetic values for tests.

---

## 16. Logging and Diagnostics

Logging should aid troubleshooting without exposing sensitive information.

Default logging must be minimal.

Debug logging must be explicitly enabled.

Use stderr for diagnostic messages.

Do not contaminate stdout when it is used for:

- Remote command output.
- JSON output.
- Script consumption.

Never log:

- AWS secrets.
- SSM session tokens.
- MFA codes.
- Remote shell input.
- Remote command output by default.
- Forwarded TCP payloads.
- Authorization headers.
- Complete signed WebSocket URLs.

Security-sensitive diagnostic fields must be redacted.

Error messages should contain enough context to troubleshoot without exposing secrets.

---

## 17. Error Handling

Fail safely and visibly.

Never ignore errors from:

- Credential loading.
- STS role assumption.
- AWS API calls.
- TLS negotiation.
- Session establishment.
- Protocol decoding.
- Terminal initialization.
- Port binding.
- Connection shutdown.

Do not silently suppress important failures.

Handle cleanup errors separately when necessary.

Never mask an authentication failure by attempting an unauthorized alternative path.

Use context-rich errors without including sensitive data.

---

## 18. Go Engineering Standards

Write idiomatic, maintainable Go.

Requirements:

- Use `gofmt`.
- Prefer clear package boundaries.
- Use `context.Context` for cancellable operations.
- Bound concurrent operations.
- Avoid goroutine leaks.
- Avoid global mutable state when practical.
- Handle errors explicitly.
- Avoid unnecessary reflection.
- Avoid `unsafe` unless justified and reviewed.
- Prefer small, testable functions.
- Document exported APIs.
- Avoid unnecessary abstraction layers.

Use interfaces primarily at genuine architectural or testing boundaries.

Do not introduce complexity without a clear benefit.

---

## 19. Testing and Security Verification

Every security-sensitive change requires appropriate tests.

Prioritize testing:

- Credential provider selection.
- STS AssumeRole behavior.
- Failed authentication.
- Incorrect IAM permissions.
- Instance resolution.
- Duplicate instance names.
- Session ownership.
- Session cleanup.
- Malformed protocol messages.
- Message size limits.
- Protocol disconnects.
- Terminal restoration.
- Command injection resistance.
- Port-forward validation.
- Loopback-only binding.
- Sensitive log redaction.

Tests must not depend on live AWS credentials by default.

Use mocks and synthetic credentials.

Live integration tests must be explicitly opted into.

Do not create billable AWS resources without explicit authorization.

Before considering a significant change complete, run:

    gofmt
    go vet ./...
    go test ./...
    go test -race ./...
    go mod verify

Run `govulncheck ./...` when the tool is available.

If a validation command cannot run, document the reason.

Do not claim tests passed unless they actually ran and passed.

---

## 20. Build Security

The application must compile into native Linux binaries.

Target platforms:

- Linux AMD64.
- Linux ARM64.

Prefer:

    CGO_ENABLED=0

where practical.

Builds should be reproducible to the extent supported by the toolchain.

Avoid embedding:

- Credentials.
- Session tokens.
- Absolute developer-specific paths.
- Local environment secrets.

Do not include sensitive debug information in published artifacts.

Version metadata may be embedded using Go linker flags.

Release binaries should not require Go to be installed.

---

## 21. Git and Version Control

This project may not initially contain a Git repository.

Do not assume `.git` exists.

Do not initialize Git unless explicitly instructed.

When Git is introduced:

- Respect existing branch conventions.
- Do not force-push.
- Do not rewrite history without authorization.
- Do not discard unrelated changes.
- Do not commit secrets.
- Do not commit generated credentials.
- Do not commit unnecessary binaries.
- Do not bypass configured security checks.
- Do not modify Git configuration without authorization.

### Mandatory Add, Commit and Push After Each Change

The project owner authorizes and requires agents to automatically stage, commit
and push every completed logical change, including code, tests, documentation
and repository instructions. Do not wait for another commit/push request.
Treat a change as the coherent task change, not each individual file edit;
finish its tests, security review and CODEX.md synchronization before committing.

After each change:

1. Inspect Git status, the branch, configured remote and the complete diff.
2. Run applicable validation and the mandatory final review. Do not commit
   known failing or unfinished work as completed; report any blocker instead.
3. Stage only task-owned files with explicit `git add` paths. Preserve unrelated
   user edits; never include secrets, credentials, debug logs or build binaries.
4. Review the staged diff and run `git diff --cached --check`.
5. Make a concise descriptive commit without attribution trailers or signatures.
6. Push the current branch to its configured upstream using a normal,
   non-force push. If no upstream exists, use an already configured intended
   remote only when the target branch is unambiguous; otherwise ask the owner.
7. Verify push success and report the commit hash, branch and remaining changes.

Use the existing Git identity. If it is missing, the owner-approved identity is
`Jason Terlecki <jterlecki@gmail.com>`; supply it with per-command `git -c`
options rather than changing repository/global Git configuration.

If Git, a remote, authentication or push permission is missing, or a push is
rejected, report the exact safe blocker and whether a local commit exists.
Never claim an unsuccessful push succeeded. Do not force-push, rewrite history,
bypass hooks, install credentials, discard changes or change remotes/configuration
to make publication work. Resolve conflicts with the owner when needed.
This standing authorization covers source commits/pushes only, not release
publication, Git initialization, AWS actions or unrelated external changes.
An explicit instruction for a particular task not to commit or push takes
precedence over this default workflow.

Do not add:

- `Co-authored-by` trailers.
- AI-generated attribution.
- Assistant signatures.
- Tool attribution in commit messages.

A `.gitignore` should exclude, as appropriate:

- Build outputs.
- Temporary files.
- Local debug logs.
- Coverage artifacts.
- Editor-specific local state.
- Secret and credential files.

Do not use broad ignore patterns that accidentally hide important project files.

---

## 22. Documentation Requirements

Maintain accurate documentation.

At minimum:

### README.md

User-facing documentation:

- Installation.
- Building.
- Usage.
- AWS prerequisites.
- Authentication.
- Role assumption.
- Session behavior.
- Port forwarding.
- Troubleshooting.
- Security expectations.
- Known limitations.

### AGENTS.md

Agent engineering and security instructions.

### CODEX.md

Authoritative repository map, file purposes, and architectural reference.

`CODEX.md` must remain continuously synchronized as required by
"Mandatory CODEX.md Synchronization"; routine synchronization requires no
separate user request or approval.

Documentation must distinguish implemented features from planned features.

Never document an unimplemented security feature as operational.

---

## 23. Architecture Changes

Before significant architectural changes:

1. Inspect the relevant implementation.
2. Identify the security boundary being changed.
3. Evaluate credential exposure risks.
4. Evaluate authentication and authorization implications.
5. Evaluate network exposure.
6. Evaluate session ownership and cleanup.
7. Determine test coverage required.
8. Implement the smallest reasonable change.
9. Update `CODEX.md`.
10. Document any remaining risks.

Do not replace security-sensitive infrastructure merely for stylistic reasons.

Do not refactor authentication or transport components casually.

---

## 24. Feature Completion Requirements

A feature is complete only when:

- Its implementation works as specified.
- Its security implications have been evaluated.
- Input validation is present.
- Error handling is appropriate.
- Relevant tests exist and pass.
- Sensitive data is protected.
- Existing behavior is preserved unless intentionally changed.
- User-facing documentation is updated.
- `CODEX.md` synchronization has been completed and verified.
- The completed change has been staged, committed and pushed under Section 21,
  or a commit/push blocker has been explicitly reported.

Do not describe incomplete features as production-ready.

Do not use dummy implementations to satisfy acceptance tests.

---

## 25. Mandatory Final Review

Before finishing a development task, the agent MUST:

1. Review the changed files.
2. Check for accidental secret exposure.
3. Check for unauthorized privilege changes.
4. Check for insecure network binding.
5. Check for missing TLS validation.
6. Check for command injection risks.
7. Check for unsafe protocol parsing.
8. Check for missing resource cleanup.
9. Run applicable tests and validation tools.
10. Compare all changed files with `CODEX.md`, update every affected section,
    and verify that file references, implementation status, security boundaries,
    and architectural relationships are accurate.
11. Summarize unresolved security risks.
12. Stage, commit and push the validated task-owned change under Section 21,
    verify the result and report any publication blocker.

The final response should briefly include:

- What changed.
- Tests performed and results.
- Security considerations.
- Known limitations.
- Whether `CODEX.md` was updated.
- Commit hash, push result and any remaining uncommitted changes.

If a security requirement could not be satisfied, explicitly disclose it.

---

## 26. Non-Negotiable Rules

The following rules apply to every change:

1. NEVER hardcode AWS credentials.
2. NEVER log AWS or SSM authentication secrets.
3. NEVER disable TLS certificate verification.
4. NEVER silently bypass IAM authorization.
5. NEVER automatically escalate remote privileges.
6. NEVER silently fall back to SSH.
7. NEVER expose forwarded ports publicly by default.
8. NEVER execute untrusted commands through a local shell.
9. NEVER trust unvalidated Session Manager protocol messages.
10. NEVER terminate sessions not owned by this process.
11. NEVER conceal security-relevant failures.
12. NEVER claim security controls exist when they do not.
13. NEVER introduce unnecessary privileged operations.
14. NEVER make security-sensitive changes without appropriate testing.
15. NEVER leave `CODEX.md` knowingly outdated.
16. NEVER assume a Git repository exists.
17. NEVER initialize Git without explicit authorization.
18. NEVER commit or publish secrets.
19. NEVER fabricate successful tests or security validation.
20. NEVER prioritize convenience over security.

---

## 27. Guiding Principle

`ssmh` is a remote-access security tool.

It operates across AWS identity, network, operating-system,
and remote-execution trust boundaries.

Every implementation decision must preserve those boundaries.

The objective is not merely to establish a connection.

The objective is to establish the correct connection, using the
correct identity, to the correct target, through an authenticated
and secure channel, with predictable behavior and no unnecessary
exposure of sensitive information.

When uncertain, choose the safer behavior, document the limitation,
and preserve the security boundary.

