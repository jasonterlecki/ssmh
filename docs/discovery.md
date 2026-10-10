# Discovery implementation status

EC2 discovery and exact Name resolution are now implemented as read-only libraries;
their SSM join and CLI `--list`/`--check`/JSON output are implemented. Check accepts
IDs or exact Names. Every session mode also resolves an ID/exact Name and requires
EC2 running before Linux/Online SSM validation. After the user enabled network access,
the normal EC2 SDK download succeeded. The pinned v1.304.0 fits the existing SDK
dependency set without unrelated upgrades; no handcrafted AWS client is used.

## EC2 discovery and exact target resolution

`ec2.Discover` uses SDK v2
[DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
with MaxResults=100. Exact-ID lookup uses the instance-id filter so requests can
remain paginated: AWS forbids combining InstanceIds with MaxResults. Name, state
and unique KEY=VALUE tag predicates are combined with AND, with at most 50 total
filters. Empty library queries include all states; CLI listing defaults to running.
Values are case sensitive and literal, not user-supplied patterns. Backslashes,
asterisks and question marks are escaped using AWS's documented
[filter syntax](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Filtering.html),
and escaped values are bounded to 255 characters before API calls. All predicates
are checked against returned metadata locally. Repeated tag
keys or a second Name predicate are rejected before calling AWS.

Every page, including empty pages, is consumed before returning sorted results.
Local bounds are 1,000 pages, 1,000 reservations and instances per page, 10,000
instances overall and 8,192 bytes per opaque token. Token cycles, duplicate IDs,
malformed metadata, cancellation or any later error discard the complete result.
Limits follow SDK response decoding and do not bound HTTP decoding allocations.
AWS inventory is eventually consistent, not a transactional snapshot.

The DTO retains only a validated ID, known state, bounded Name, optional canonical
IPv4 address and the caller's selected region. Missing IPv4 is valid, including
IPv6-only instances; no local DNS or reachability probe is performed. Tags are
bounded and duplicate keys, missing values, invalid Unicode and control characters
are refused. Names still require terminal sanitization at display boundaries.
Public addresses, arbitrary SDK objects, credentials and unrelated tags are not
retained. Callers must pass the region corresponding to their selected SDK client.

`ec2.Resolve` requires exactly one ID or exact, case-sensitive Name match after
complete pagination. No match yields ErrNotFound; duplicate Names yield
ErrAmbiguous and require an explicit instance ID. Stopped or offline duplicates
are never discarded merely to select another machine. Resolution does not prove
running state, Linux/Online SSM registration or StartSession authorization; those
are distinct checks before connecting. No API mutates resources or starts a session.
Offline mocks and signed SDK HTTP/XML fixtures validate behavior, not live AWS.

## Read-only CLI listing

`ssmh --list` calls both inventories using clients constructed from the same
selected SDK config (including explicit roles and resolved region), then joins
only exact IDs. It defaults to EC2 state running and includes only SSM Online
registrations. `--state` selects a different exact state. Unregistered, offline,
nonmatching EC2 records and SSM records with no matching EC2 row are omitted.
Platform is shown, not treated as proof of native/Linux session compatibility.
Reports are eventually consistent; even a running/Online row does not prove
current reachability, document compatibility or StartSession permission.

`--name` and repeated unique `--tag KEY=VALUE` filters are exact and case-sensitive.
Invalid filter syntax/counts/escaped lengths are refused before authentication.
Listing never starts/terminates a permission-test session, opens a socket listener,
uses terminal raw mode or consumes stdin. MFA, when explicitly needed for a role,
uses the existing secure controlling-terminal prompt and is disabled before output.
Both API results must complete successfully before stdout receives any inventory.
Errors discard results; no partial or failed inventory is presented as success.

Human output contains ID, sanitized Name, state, SSM status, platform, private IP
and region. `--json` writes a sorted array with keys instance_id, name, state,
ssm_status, platform, private_ip and region; an empty success is `[]`, not null.
Wire JSON is ASCII-only with Unicode escapes, preserving exact decoded Name
values without embedding terminal/bidi formatting characters. No ANSI, progress,
identity data, session tokens or unrelated SDK fields enter stdout. Quiet does
not suppress requested data. Verbose/debug identity/stage diagnostics use bounded
stderr; default listing makes no additional STS identity request.

The single --timeout budget covers authentication, inventories, formatting and
output. A private stdout Stream bounds pipe/TTY writing to the remaining budget
and at most ten seconds; regular files retain kernel-blocking limitations.
If a consumer closes/stalls, failure is reported and private descriptors/HTTP
pools close. Output I/O failure can leave incomplete bytes: discard that output
and check the process exit status. Listing requires ec2:DescribeInstances and
ssm:DescribeInstanceInformation, not StartSession/TerminateSession permissions.

`ssm.Inventory` uses the SDK v2
[DescribeInstanceInformation API](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeInstanceInformation.html)
with the documented
[ResourceType=EC2Instance filter](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_InstanceInformationStringFilter.html).
It requests 50 records per page and follows tokens even through empty pages.
It retains only validated EC2 IDs, reported ping status, platform and optional
[agent version](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_InstanceInformation.html).
It never starts or terminates a session, modifies resources, or performs a
remote command. It uses the caller's already selected SDK identity and region.

Local safety limits are 1,000 pages, 10,000 records and 8,192 bytes per token.
Cycles, duplicate IDs, malformed/unknown metadata, oversized pages, cancellation
and any later API failure discard the complete accumulated result. No partial
inventory is returned as success. Successful rows are sorted by instance ID;
an empty successful inventory is an empty collection. Concurrent changes can
cause duplicate IDs; an explicit retry may be appropriate. AWS pagination does
not provide a transactional snapshot. SDK response decoding happens before
these checks, so these limits are not a bound on HTTP response-body decoding.

Online is an agent report, not proof that the instance is running, that an IAM
principal can start a session, or that the selected transport is usable. The
implemented listing/check joins authenticated EC2 discovery with this SSM
metadata and preserve those distinctions. Live AWS verification remains pending.

## Exact-target connection readiness

### Read-only CLI check

`ssmh --check -i ID_OR_EXACT_NAME [--json]` resolves SDK credentials/region and
reads STS caller metadata, then resolves exactly one EC2 target after all pages.
No exact match fails; duplicate Names fail even if only one instance is running.
It requires EC2 running, complete exact-ID SSM Linux/Online registration and the
strict native non-KMS default-version shell document. The selected native backend
is compiled into the executable; plugin remains unsupported and is refused before
authentication. Check validates the default shell, not command/forwarding/custom
document sessions; those session options remain mutually exclusive with --check.

STS account/ARN metadata is shown when available. Only a classified explicit STS
AccessDenied/AccessDeniedException makes it unavailable without aborting: no
alternate role/provider/account is tried, and all remaining APIs use the same
selected SDK config. Expired/invalid credentials, TLS/network errors, malformed
identity, unknown failures and cancellation stop the check. This is a metadata
exception, not a bypass of EC2/SSM authorization or failure of explicit AssumeRole.
Ordinary verbose connection/list identity failures remain fatal.

Check uses only GetCallerIdentity, DescribeInstances, DescribeInstanceInformation
and GetDocument. It never starts or immediately terminates a permission-test
session, opens a data channel/listener, runs a command or alters a remote resource.
Passing these read APIs does not exercise StartSession/OpenDataChannel permissions.
Document administrators remain trusted: reading $DEFAULT cannot pin the document
or prevent a concurrent authorized change. Agent/EC2 reports can change after
checking; running/Online does not establish live data-channel connectivity.

The human report calls its result "Prerequisites passed" with an explicit
authorization/connectivity disclaimer. JSON is one ASCII-encoded object: profile,
optional account_id/identity_arn, identity_status, instance (listing's seven fields),
backend, document, ready and session_permissions_verified. ready means the inspected
prerequisites passed; session_permissions_verified is always false. With denied
STS metadata, identity_status is unavailable_access_denied and account/ARN are
omitted. No partial or failed report is emitted; stdout failures may leave
incomplete bytes, so consumers must check exit status and discard them.
Quiet still prints requested results; verbose/debug diagnostics remain on stderr.
Private descriptor/write/deadline, MFA disabling and HTTP cleanup rules match listing.

### Existing connection setup

Shell/command/forwarding first resolves the ID or literal exact Name through the
selected SDK EC2 client, following all pages and rejecting absence or ambiguity.
It requires running before constructing the SSM session-control client. Stopped
duplicates are not filtered out to select a running Name match. Only the resolved
validated ID reaches SSM; Name text is never used as a session target or emitted
raw in diagnostics. Even explicit-ID sessions now need ec2:DescribeInstances.
Resolution and state checks share the original setup deadline; failures close
the selected HTTP pool and any loopback listener reserved before authentication.
Metadata is eventually consistent, so these reads do not guarantee future state.

Setup then calls `ssm.Online` through the read-only
`StatusAPI`, with the documented InstanceIds filter containing only the validated
target ID. It requests 50-row pages and follows every token, including empty pages,
before accepting exactly one Online EC2 registration. A first matching row alone
is not sufficient: later duplicates, failures or malformed pagination discard it.

The check reuses inventory validation for EC2 resource type, ID, known ping/platform
and optional numeric agent version. Unexpected IDs, missing/unknown metadata,
oversized pages, repeated/oversized tokens or the 1,000-page limit fail closed.
Cancellation is checked before and after each SDK call. Every failure returns an
empty record, including offline/unregistered targets. Success returns only ID,
resource type, ping, platform and optional agent version, not arbitrary SDK
Name/IP/hostname or association fields. Local bounds follow SDK decoding and do
not limit response-body decoding itself.

The CLI separately requires Linux. Neither prerequisite exercises session permission
or creates a permission-test session. Concurrent registration changes
can cause a duplicate error; an explicit retry may be appropriate.
