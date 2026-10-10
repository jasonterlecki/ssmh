# Project: ssmh - AWS Systems Manager Remote Shell Client

## Objective

Create a production-quality command-line application named `ssmh`,
written entirely in Go, that provides an SSH-like experience for
connecting to Amazon EC2 instances using AWS Systems Manager (SSM)
Session Manager instead of the SSH protocol.

The application must compile into a native Linux binary.

The goal is to provide a lightweight, secure, convenient alternative
to SSH for AWS-managed EC2 instances.

Example:

    ssmh -i i-0123456789abcdef0

This should open an interactive shell on the specified EC2 instance,
provided it is registered with AWS Systems Manager and supports
Session Manager.

The application must NOT require:
- An SSH daemon on the remote instance.
- Port 22 to be open.
- SSH keys.
- A public IP address.
- A bastion host.
- AWS CLI installed on the client.

Use AWS IAM authentication and native Systems Manager sessions.

---

# 1. Technology Requirements

Language:
- Go, using the latest stable Go version compatible with the project.

Platform:
- Linux AMD64 (mandatory).
- Linux ARM64 (mandatory).

AWS integration:
- AWS SDK for Go v2.
- AWS Systems Manager API.
- AWS STS API.
- AWS EC2 API for instance discovery.
- AWS shared configuration and credential providers.

Terminal:
- Native Linux terminal support.
- Proper TTY/raw-mode handling.
- Terminal dimensions and resize events.
- ANSI escape sequence support.
- Correct signal handling.

Dependencies:
- Prefer standard Go libraries.
- Use established, maintained Go packages where necessary.
- Avoid unnecessary third-party dependencies.

Build:
- Standard Go build tooling.
- Reproducible builds.
- Version information embedded at build time.
- Makefile for common operations.

The application should be distributed as a single executable.

No Python, Node.js, or Java runtime dependencies.

---

# 2. Critical Architectural Requirement

The application must use AWS Systems Manager Session Manager
as its transport mechanism.

It must NOT simply open an SSH connection through an SSM tunnel.

There are two acceptable implementation strategies:

A. Preferred: Native Go Session Manager Transport

Implement the Session Manager data channel in Go using the
official AWS Session Manager protocol and available open-source
AWS implementations as references.

This includes:

- Calling SSM StartSession.
- Receiving the session ID, stream URL, and token.
- Establishing the authenticated WebSocket data channel.
- Implementing the necessary Session Manager message framing.
- Handling the session handshake.
- Supporting input and output messages.
- Handling acknowledgements and sequencing as required.
- Supporting interactive shell sessions.
- Supporting terminal resize messages.
- Handling session termination and disconnections.

AWS SDK v2 can start and stop sessions, but it does not itself
provide the complete interactive data-channel implementation.

Do not assume the WebSocket is a simple raw text stream.

B. Compatibility fallback: Official Session Manager Plugin

If implementing the native protocol is impractical or cannot
be validated reliably, support the official AWS Session Manager
Plugin as an explicitly documented compatibility backend.

The fallback must:

- Use AWS SDK v2 for authentication and StartSession.
- Pass the session response to the official plugin.
- Preserve terminal input and output.
- Properly handle cleanup and termination.
- Detect whether the plugin is installed.
- Display an actionable installation error if missing.

Do not silently substitute AWS CLI.

The intended long-term architecture is a fully native Go client
without external runtime dependencies.

Do not claim the application is dependency-free if it requires
the Session Manager Plugin.

---

# 3. Command-Line Interface

Application name:

    ssmh

Use conventional GNU-style command-line arguments.

Mandatory argument:

    --instance, -i

Specifies the target EC2 instance.

Example:

    ssmh --instance i-0123456789abcdef0

Support instance IDs directly.

If the supplied value is not an instance ID, optionally resolve
it against EC2 Name tags.

If multiple instances match, display an interactive selection
or return an ambiguity error in noninteractive mode.

---

# 4. AWS Authentication Options

## --profile / -p

Optional AWS CLI profile.

Examples:

    ssmh -i i-0123456789abcdef0 -p production

    ssmh --instance i-0123456789abcdef0 \
         --profile development

If omitted, use the normal AWS SDK credential chain.

Support:

- Environment credentials.
- AWS shared credentials files.
- AWS shared configuration files.
- AWS IAM Identity Center / SSO profiles.
- EC2 instance profiles.
- ECS task credentials.
- AssumeRole profiles.
- Credential process providers.

Do not manually parse credentials if the SDK already supports
the authentication method.

Never print secret credentials or session tokens.

## --arn

Optional IAM role ARN to assume before connecting.

Example:

    ssmh -i i-0123456789abcdef0 \
         --profile management \
         --arn arn:aws:iam::123456789012:role/CloudAdmin

Implementation:

1. Load the initial AWS credentials.
2. If --arn is specified, call STS AssumeRole.
3. Use the assumed-role credentials for subsequent API calls.
4. Automatically refresh temporary credentials when supported.
5. Handle failed role assumptions with clear error messages.

Additional arguments:

    --session-name

Optional STS role session name.

Default:

    ssmh-<generated-unique-identifier>

    --external-id

Optional STS external ID.

    --mfa-serial

Optional MFA device ARN.

    --mfa-token

Optional MFA token, preferably obtained interactively when
needed rather than exposed in process arguments.

Do not implement MFA prompting in a way that interferes with
interactive terminal handling.

---

# 5. AWS Region Support

Arguments:

    --region, -r

Optional AWS region.

Examples:

    ssmh -i i-0123456789abcdef0 -r ca-central-1

    ssmh -i i-0123456789abcdef0 \
         -p production \
         -r us-east-1

Region resolution priority:

1. Explicit --region argument.
2. Region configured in the AWS SDK environment/configuration.
3. If no region is available, provide a clear error.

Do not silently use an arbitrary default region.

Support AWS commercial partitions and design ARN handling to
remain compatible with other AWS partitions.

---

# 6. Interactive Shell

Default behavior:

    ssmh -i i-0123456789abcdef0

Connect to the instance and open an interactive SSM shell.

Requirements:

- Interactive stdin/stdout.
- Raw terminal mode where appropriate.
- Proper handling of Ctrl+C.
- Proper handling of Ctrl+D.
- Terminal resize propagation.
- ANSI colors.
- Cursor movement.
- Interactive applications.
- Terminal echo behavior.
- UTF-8 support.
- Full-screen terminal programs where supported.

The user should be able to run commands such as:

    ls
    top
    htop
    vim
    nano
    sudo -i

Subject to the capabilities of the remote SSM session.

Restore the local terminal state on every exit path.

This includes:

- Normal disconnect.
- Ctrl+C / SIGINT.
- SIGTERM.
- Remote session termination.
- Network failure.
- Authentication failure after terminal initialization.

Do not leave the user's local terminal in raw mode.

Handle Ctrl+C intelligently.

During an interactive session, Ctrl+C should normally be passed
through to the remote shell rather than automatically terminating
the local client.

Provide an explicit local escape sequence for disconnecting
from the session.

For example:

    Enter, then ~.

Use a documented escape sequence compatible with terminal input.

---

# 7. Remote Command Execution

Support an optional remote command.

Argument:

    --command, -c

Example:

    ssmh -i i-0123456789abcdef0 \
         -c "uname -a"

Another example:

    ssmh -i i-0123456789abcdef0 \
         -c "sudo systemctl status nginx"

Requirements:

- Execute through a supported SSM session document.
- Do not use SSH.
- Do not use AWS Run Command as an implicit fallback.
- Properly quote and preserve commands.
- Display remote stdout and stderr where supported.
- Avoid an interactive terminal when possible.
- Propagate the remote exit code if it can be reliably obtained.

If the chosen SSM interactive-command mechanism cannot
reliably provide a remote exit status, implement and document
a safe exit-code propagation mechanism.

Clearly distinguish:

- Successful remote execution.
- Remote command failure.
- Failure to establish an SSM session.
- Authentication failure.
- Connection interruption.

Be careful not to claim separate stdout and stderr streams
when SSM only provides a combined terminal stream.

Support commands that contain spaces, quotes, shell
metacharacters, and non-ASCII characters.

Never interpolate command input into a locally executed shell.

---

# 8. Instance Discovery

Support:

    ssmh --list

List EC2 instances that are available for SSM connections.

Optional filters:

    --state running
    --tag Environment=Production
    --name webserver
    --region ca-central-1

Display useful columns:

    INSTANCE ID
    NAME
    STATE
    SSM STATUS
    PLATFORM
    PRIVATE IP
    REGION

Example:

    INSTANCE ID          NAME          STATE    SSM       PRIVATE IP
    i-0123456789abcdef0  web-prod-01   running  Online    10.0.1.20
    i-0987654321abcdef0  api-prod-01   running  Online    10.0.2.15

Use EC2 DescribeInstances and SSM DescribeInstanceInformation.

Handle pagination for all list operations.

Do not assume that every running EC2 instance is registered
with Systems Manager.

Support:

    ssmh --list --json

Output machine-readable JSON.

JSON output must not contain ANSI formatting, progress messages,
or other unrelated text.

When no instance is specified and stdin is interactive, an
optional instance selection interface may be offered.

Keep this simple and lightweight.

---

# 9. Instance Name Resolution

Allow connecting with an EC2 Name tag.

Example:

    ssmh -i web-prod-01

Resolution logic:

1. Search the selected region for matching EC2 Name tags.
2. Prefer exact matches.
3. If exactly one instance matches, select it.
4. If multiple instances match, require explicit selection.
5. Verify SSM availability before connecting.

Do not silently select an arbitrary matching instance.

If the instance cannot be located, display a useful diagnostic.

Example:

    ERROR: No EC2 instance named 'web-prod-01'
    was found in ca-central-1.

---

# 10. Port Forwarding

Support local TCP port forwarding through AWS SSM.

Argument:

    --forward, -L

Syntax:

    --forward LOCAL_PORT:REMOTE_PORT

Example:

    ssmh -i i-0123456789abcdef0 \
         -L 8080:80

This should forward:

    localhost:8080 -> remote instance:80

Use the SSM port-forwarding session document:

    AWS-StartPortForwardingSession

Do not require SSH.

Also support forwarding to a remote host accessible from
the EC2 instance.

Syntax:

    --forward-host LOCAL_PORT:REMOTE_HOST:REMOTE_PORT

Example:

    ssmh -i i-0123456789abcdef0 \
         --forward-host 15432:database.internal:5432

Use:

    AWS-StartPortForwardingSessionToRemoteHost

This is useful for:

- Private RDS databases.
- Internal services.
- Private web applications.
- Administrative interfaces.
- Services reachable only within a VPC.

Requirements:

- Bind only to 127.0.0.1 by default.
- Do not expose forwarded ports publicly by default.
- Validate port ranges.
- Handle port conflicts.
- Support graceful shutdown.
- Display the forwarding target and listening address.
- Use the official SSM port-forwarding protocol.

If the native backend does not yet implement binary port
forwarding, use the documented plugin compatibility backend
rather than pretending a shell data channel is a TCP tunnel.

---

# 11. Session Configuration

Support the following options:

    --document

Optional SSM session document name.

Default to AWS's standard Session Manager shell behavior
when no document is specified.

Do not hardcode a document unnecessarily.

    --reason

Optional reason for starting the session.

Example:

    ssmh -i i-0123456789abcdef0 \
         --reason "Production incident investigation"

Pass this through to the SSM StartSession API.

    --timeout

Timeout for establishing the session.

Default:

    30 seconds

    --duration

Optional maximum local session duration.

Example:

    --duration 1h

The client should terminate its session once this limit
has elapsed.

Clearly document that local client duration limits do not
override server-side SSM session policies.

    --backend

Values:

    native
    plugin
    auto

Default:

    auto

Prefer the native backend when the required feature is
fully implemented and validated.

Fall back only when the required compatibility backend
is available.

Never silently downgrade security or change the operation
being requested.

---

# 12. Connection Diagnostics

Implement:

    ssmh --check -i i-0123456789abcdef0

This command checks whether an SSM connection can reasonably
be established without starting an interactive shell.

Validate:

- AWS credentials can be resolved.
- STS identity is accessible when permitted.
- The configured region.
- The target EC2 instance exists.
- The instance is running.
- The instance is registered with SSM.
- The SSM agent reports Online.
- The selected session backend is available.

Report clear results.

Example:

    AWS Profile:       production
    AWS Region:        ca-central-1
    AWS Account:       123456789012
    Identity:          CloudAdmin
    Instance:          i-0123456789abcdef0
    Instance State:    running
    SSM Status:        Online
    Backend:           native

    Ready to connect.

Do not claim IAM permissions have been fully verified
unless they have actually been exercised.

Do not start and immediately terminate a session just
to test permissions unless explicitly requested.

When a check fails, provide actionable diagnostics.

---

# 13. Verbose Logging and Debugging

Arguments:

    --verbose, -v
    --debug
    --quiet, -q

Behavior:

Default:
- Minimal informational messages.
- Useful errors.

Verbose:
- Credential provider type, when safely available.
- Selected region.
- Instance resolution.
- Connection stages.
- Session termination reason.

Debug:
- Additional protocol diagnostic information.
- AWS API request timing.
- WebSocket connection state.
- Retry information.

Never log:

- AWS secret access keys.
- AWS session tokens.
- SSM session tokens.
- Authorization headers.
- Remote shell input containing secrets.
- Raw terminal payloads by default.

Use stderr for diagnostics.

Keep stdout clean for command output and JSON responses.

---

# 14. Security Requirements

Security is a primary design objective.

Requirements:

- Never persist AWS credentials.
- Never print secrets.
- Never disable TLS verification.
- Validate server certificates.
- Use secure WebSocket connections.
- Respect AWS IAM authorization.
- Do not bypass Session Manager controls.
- Do not silently escalate privileges.
- Do not use SSH as a fallback.
- Bind forwarded local ports to loopback by default.
- Restrict file permissions when generating local files.
- Avoid command injection.
- Avoid arbitrary shell execution on the client.
- Never expose the SSM session token in logs.

The application must respect existing AWS Systems Manager
Session Manager preferences and applicable IAM policies.

Document the difference between ordinary SSM shell sessions,
SSH-over-SSM, and SSM port-forwarding sessions.

Do not claim that Session Manager logs all traffic:
port-forwarding sessions and SSH-over-SSM have different
logging and visibility characteristics.

---

# 15. Session Lifecycle

Implement the full lifecycle:

1. Resolve AWS credentials.
2. Assume the requested IAM role, if specified.
3. Resolve the AWS region.
4. Resolve the instance.
5. Validate basic instance and SSM availability.
6. Start the SSM session.
7. Connect the selected transport backend.
8. Establish interactive or forwarding functionality.
9. Process input/output.
10. Handle disconnects and signals.
11. Terminate the session cleanly.

Use SSM TerminateSession when appropriate.

Ensure cleanup on normal exits and recoverable errors.

Do not terminate a session owned by another client.

Use Go contexts and cancellation to manage active operations.

Avoid goroutine leaks.

Implement suitable bounded retries for transient connection
failures.

Do not blindly restart a remote command after a disconnect,
because doing so could execute it more than once.

---

# 16. Terminal and Signal Handling

Linux terminal behavior is extremely important.

Use golang.org/x/term or an equivalent maintained package.

Requirements:

- Detect whether stdin is a terminal.
- Enter raw mode only when needed.
- Restore original terminal settings.
- Handle SIGWINCH.
- Propagate terminal dimensions where supported.
- Preserve terminal output.
- Support piped input where technically appropriate.
- Handle EOF gracefully.
- Handle SIGINT and SIGTERM.

Do not assume every invocation is interactive.

Examples that should work correctly:

    ssmh -i i-0123456789abcdef0

    ssmh -i i-0123456789abcdef0 \
         -c "hostname"

    ssmh -i i-0123456789abcdef0 \
         -c "cat /etc/os-release" > os-release.txt

Ensure redirected output is not polluted with local status
messages or terminal control sequences unnecessarily generated
by the client.

---

# 17. Error Handling

Use descriptive, actionable errors.

Examples:

Missing instance:

    ERROR: Missing required instance.
    Usage: ssmh --instance INSTANCE_ID

Credentials unavailable:

    ERROR: Unable to load AWS credentials.
    Check AWS_PROFILE, AWS_CONFIG_FILE,
    or your IAM Identity Center session.

Instance unavailable:

    ERROR: Instance i-0123456789abcdef0
    is not currently available through SSM.

Role assumption failure:

    ERROR: Unable to assume IAM role:
    arn:aws:iam::123456789012:role/CloudAdmin

Session permission denied:

    ERROR: Access denied when starting
    the Systems Manager session.

Connection failure:

    ERROR: Unable to establish the
    Session Manager data channel.

Use meaningful process exit codes and document them.

---

# 18. Version and Help

Support:

    ssmh --help
    ssmh --version

Example:

    ssmh version 1.0.0
    Go version: go1.x
    OS/Arch: linux/amd64

Generate a useful help screen.

Example:

    ssmh - AWS Systems Manager Remote Shell

    Usage:
      ssmh [options]

    Connection:
      -i, --instance       EC2 instance ID or Name tag
      -p, --profile        AWS profile
      -r, --region         AWS region
          --arn            IAM role ARN to assume
          --session-name   STS role session name
          --external-id    STS external ID
          --mfa-serial     MFA device ARN
          --mfa-token      MFA token

    Execution:
      -c, --command        Execute remote command
          --document       SSM session document
          --reason         Session reason
      -L, --forward        Local port forwarding
          --forward-host   Forward to remote host

    Discovery:
          --list           List instances
          --name           Filter by Name tag
          --state          Filter by instance state
          --tag            Filter by tag
          --json           JSON output
          --check          Check connection readiness

    Runtime:
          --timeout        Connection timeout
          --duration       Session duration limit
          --backend        native, plugin, auto
      -v, --verbose        Verbose output
          --debug          Debug output
      -q, --quiet          Suppress informational output

    General:
      -h, --help           Display help
          --version        Display version

---

# 19. Project Organization

Use a clean Go project structure.

Suggested logical components:

- CLI argument parsing.
- AWS configuration and authentication.
- STS role assumption.
- EC2 discovery.
- SSM API integration.
- Session Manager transport.
- Terminal management.
- Port forwarding.
- Error handling.
- Diagnostics.

Do not overengineer the application.

Avoid introducing a plugin framework, dependency injection
framework, or unnecessary abstraction layers.

Use Go interfaces where they provide meaningful testability
or separate protocol backends.

Follow existing repository conventions if the repository
already contains source code or project instructions.

Before creating files, inspect the repository.

Respect existing AGENTS.md, README.md, Makefile, and other
project conventions if present.

Do not invent a large directory structure without a reason.

---

# 20. Build and Release

Provide a Makefile with at least:

    make build
    make test
    make lint
    make clean
    make release

Build output:

    dist/ssmh-linux-amd64
    dist/ssmh-linux-arm64

Embed version metadata using Go linker flags.

Use:

    CGO_ENABLED=0

where practical.

If any library prevents static compilation, document why
and prefer a compatible implementation.

The resulting native backend binary should run without
requiring Go to be installed on the target Linux system.

Provide installation instructions.

Example:

    sudo install -m 755 dist/ssmh-linux-amd64 \
        /usr/local/bin/ssmh

---

# 21. Testing Requirements

Implement meaningful automated tests.

At minimum:

- CLI argument parsing.
- Required argument validation.
- AWS region resolution.
- AWS profile selection.
- STS role assumption configuration.
- Instance ID validation.
- Instance Name tag resolution.
- Duplicate Name tag handling.
- EC2 pagination.
- SSM availability checks.
- Session lifecycle.
- Session cleanup.
- Signal handling.
- Command quoting.
- Command exit-code behavior.
- Port-forward argument validation.
- Local bind restrictions.
- Error message generation.

Use mocks or interfaces for AWS API calls.

Do not require live AWS credentials for unit tests.

Native transport tests should cover:

- Session message framing.
- Protocol handshake.
- Input/output messages.
- Acknowledgements.
- Sequence handling.
- Fragmentation.
- Disconnects.
- Timeouts.
- Malformed messages.

Use test fixtures based on verified protocol behavior.

Do not invent protocol behavior just to make tests pass.

Live AWS integration tests should be optional and explicitly
enabled.

Never create billable AWS resources during ordinary unit tests.

---

# 22. Documentation

Create a comprehensive README.md covering:

1. What ssmh does.
2. Installation.
3. Build instructions.
4. AWS authentication.
5. AWS IAM Identity Center / SSO.
6. Assuming IAM roles.
7. Basic shell usage.
8. Instance discovery.
9. Remote commands.
10. Port forwarding.
11. Troubleshooting.
12. Security considerations.
13. Required IAM permissions.
14. Backend selection and dependencies.
15. Known limitations.

Include practical examples.

Document that the remote instance must:

- Have SSM Agent installed and running.
- Be managed by AWS Systems Manager.
- Have an appropriate IAM instance profile.
- Have connectivity to required AWS Systems Manager endpoints.
- Be authorized for Session Manager use.

Explain that VPC endpoints may be used for private instances.

Provide a minimal example IAM policy for a connecting user,
with least-privilege guidance.

Include the relevant permissions as appropriate:

- ssm:StartSession
- ssm:TerminateSession
- ssm:ResumeSession
- ssm:DescribeInstanceInformation
- ec2:DescribeInstances
- sts:AssumeRole when applicable

Ensure policies are scoped correctly to instances, session
documents, and the user's own sessions where appropriate.

Do not suggest broad administrator permissions as a requirement.

---

# 23. Example Usage

Basic session:

    ssmh -i i-0123456789abcdef0

Using a profile:

    ssmh -i i-0123456789abcdef0 -p production

Using an IAM role:

    ssmh -i i-0123456789abcdef0 \
         --arn arn:aws:iam::123456789012:role/CloudAdmin

Using both:

    ssmh -i i-0123456789abcdef0 \
         -p management \
         --arn arn:aws:iam::123456789012:role/CloudAdmin

Specifying a region:

    ssmh -i i-0123456789abcdef0 \
         -r ca-central-1

Connecting by Name tag:

    ssmh -i web-prod-01 -p production

Executing a command:

    ssmh -i i-0123456789abcdef0 \
         -c "df -h"

Opening a root shell through sudo, if permitted:

    ssmh -i i-0123456789abcdef0 \
         -c "sudo -i"

Forwarding a local port:

    ssmh -i i-0123456789abcdef0 \
         -L 8080:80

Forwarding to a private database:

    ssmh -i i-0123456789abcdef0 \
         --forward-host 15432:db.internal:5432

Listing instances:

    ssmh --list -p production

Checking connectivity:

    ssmh --check \
         -i i-0123456789abcdef0

Debugging:

    ssmh -i i-0123456789abcdef0 --debug

---

# 24. Implementation Priorities

Implement the project in dependency order.

Phase 1:
- Repository inspection.
- CLI structure.
- AWS SDK v2 configuration.
- AWS credential chain.
- AWS profile support.
- Region support.
- STS AssumeRole.
- SSM StartSession and TerminateSession.

Phase 2:
- Functional interactive SSM shell.
- Terminal input and output.
- Terminal cleanup.
- Signal handling.
- Session lifecycle.

Phase 3:
- EC2 discovery.
- Instance Name tag resolution.
- SSM status validation.
- List and check operations.

Phase 4:
- Remote command execution.
- Correct exit-code handling.
- Noninteractive behavior.

Phase 5:
- Native SSM port forwarding.
- Remote-host forwarding.
- Connection diagnostics.

Phase 6:
- Comprehensive tests.
- Documentation.
- Release builds.
- Final validation.

Prioritize a fully functional basic interactive shell before
adding advanced features.

Do not build an elaborate CLI around a nonfunctional transport.

If a native transport feature is not complete, clearly mark
it as unsupported and provide the official plugin compatibility
implementation when practical.

---

# 25. Acceptance Criteria

The project is considered successful when:

1. `go build` completes successfully.

2. A Linux AMD64 binary is produced.

3. A Linux ARM64 binary is produced.

4. `ssmh --help` displays all supported options.

5. `ssmh -i INSTANCE_ID` can establish an interactive
   SSM shell using a supported backend.

6. AWS profiles work through the SDK credential chain.

7. `--arn` correctly assumes an IAM role before connecting.

8. The application does not require an SSH daemon, SSH keys,
   SSH port 22, or a public IP address.

9. Ctrl+C, Ctrl+D, terminal resizing, and disconnects
   are handled correctly.

10. The local terminal is restored after the session ends.

11. Session cleanup does not leave unnecessary active
    SSM sessions.

12. Instance discovery works.

13. Errors are readable and actionable.

14. Automated unit tests pass.

15. The README provides working usage examples.

16. The application does not expose AWS secrets.

17. No external runtime dependencies exist for the native
    backend.

18. Any remaining compatibility-backend dependencies
    are explicitly documented.

---

# 26. Development Instructions for Codex

You are responsible for implementing this application,
not merely producing an architectural proposal.

Start by inspecting the repository.

If the repository is empty, initialize a clean Go project.

If repository instructions exist, follow them.

Create a brief implementation plan, then begin coding.

Do not ask for confirmation between development phases.

Make sensible engineering decisions.

Prefer correctness and maintainability over unnecessary features.

Use established AWS SDK v2 functionality whenever possible.

Research the official AWS Session Manager protocol and reference
implementations before attempting native session transport.

Do not guess at undocumented protocol framing or invent
unsupported API functionality.

If a necessary capability is unavailable through AWS SDK v2,
implement it using a suitable maintained Go library, a verified
native protocol implementation, or the documented compatibility
backend.

Verify critical AWS behavior against official documentation.

Run:

    gofmt
    go vet
    go test ./...
    go build

Also run the race detector where appropriate.

Build both Linux architectures.

Fix compiler errors, failing tests, and lint problems.

Do not leave placeholder functions or mock transport logic
in production code.

Do not claim successful live AWS connectivity unless it has
actually been tested against AWS.

At completion, report:

- Features implemented.
- Features not yet implemented.
- Supported transport backends.
- External runtime dependencies, if any.
- Tests performed.
- Build artifacts produced.
- Known limitations.
- Exact commands needed to run the application.

Do not add AI attribution, Co-authored-by trailers,
or assistant signatures to Git commits or source files.

The final result should be a functional, secure, maintainable
Go-based AWS Systems Manager remote shell application named:

    ssmh
