# IAM permissions and deployment prerequisites

This guide describes the current development client, not a certified deployment.
Policies below are review templates, not policies that `ssmh` installs. No live
AWS authorization test has been performed. Use temporary SDK credentials; do not
create long-lived access keys to use these examples.

## Caller permissions used by the implementation

| Operation | Permission | Scope |
| --- | --- | --- |
| Resolve ID/Name and require running for every session, list or check | `ec2:DescribeInstances` | `Resource: "*"`; no resource-level authorization is listed for this action |
| Check Linux/Online registration, or read library inventory | `ssm:DescribeInstanceInformation` | `Resource: "*"`; no resource-level authorization is listed for this action |
| Read the selected default-version document before creation | `ssm:GetDocument` | Exact approved document ARN |
| Create the requested shell/command session, or library forwarding session | `ssm:StartSession` | Exact target instance and approved document ARNs |
| Establish the native data channel | `ssmmessages:OpenDataChannel` | See the unresolved scoping distinction below |
| Clean up a session started by this process | `ssm:TerminateSession` | Caller-owned sessions only |
| Explicit `--arn`, or a role profile | `sts:AssumeRole` | Exact approved role, plus its trust policy |

The [Systems Manager authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ssm.html)
defines the document/instance/session resource types and the session system-tag
conditions. Keep the necessary wildcard for DescribeInstanceInformation in its
own statement. An API filter is not an IAM restriction: this read permission can
expose managed-node metadata beyond the selected target. The client does not
call SendCommand, ResumeSession, DescribeSessions, CreateDocument or UpdateDocument.

Verbose/debug sessions/listing and every read-only check call
[STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
That operation requires no IAM allow and does not prove SSM authorization.
Successful credential loading and Online status also do not establish session
permission. Read-only --list/--check and connection Name/state validation are implemented. The forwarding library's
StartForward selects only the two AWS-managed port-forwarding documents, with
explicit host/port parameters. It requires StartSession authorization for that
target/document and caller-owned TerminateSession cleanup, not GetDocument.
CLI forwarding now uses this helper; the shell policy below is not a forwarding
grant and should not be broadened without deliberate approval.

## Single-instance IAM-user example

This example is for a **direct IAM user**, not an assumed role or an IAM Identity
Center session. Replace `aws`, `ca-central-1`, `123456789012` and the instance ID
with the actual partition, region, account and approved target. Review the default
shell document first. The document must already exist and satisfy the client's
document/key preflight; the caller does not need permission to create preferences.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ResolveTargetState",
      "Effect": "Allow",
      "Action": "ec2:DescribeInstances",
      "Resource": "*",
      "Condition": {"StringEquals": {"aws:RequestedRegion": "ca-central-1"}}
    },
    {
      "Sid": "ReadRegistration",
      "Effect": "Allow",
      "Action": "ssm:DescribeInstanceInformation",
      "Resource": "*",
      "Condition": {"StringEquals": {"aws:RequestedRegion": "ca-central-1"}}
    },
    {
      "Sid": "ReadApprovedShellDocument",
      "Effect": "Allow",
      "Action": "ssm:GetDocument",
      "Resource": "arn:aws:ssm:ca-central-1:123456789012:document/SSM-SessionManagerRunShell"
    },
    {
      "Sid": "StartApprovedShell",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": [
        "arn:aws:ec2:ca-central-1:123456789012:instance/i-0123456789abcdef0",
        "arn:aws:ssm:ca-central-1:123456789012:document/SSM-SessionManagerRunShell"
      ],
      "Condition": {"Bool": {"ssm:SessionDocumentAccessCheck": "true"}}
    },
    {
      "Sid": "OpenOwnDataChannel",
      "Effect": "Allow",
      "Action": "ssmmessages:OpenDataChannel",
      "Resource": "arn:aws:ssm:ca-central-1:123456789012:session/${aws:userid}-*"
    },
    {
      "Sid": "EndOwnTargetSessions",
      "Effect": "Allow",
      "Action": "ssm:TerminateSession",
      "Resource": "arn:aws:ssm:ca-central-1:123456789012:session/${aws:username}-*",
      "Condition": {
        "StringEquals": {
          "ssm:resourceTag/aws:ssmmessages:session-id": "${aws:userid}",
          "ssm:resourceTag/aws:ssmmessages:target-id": "i-0123456789abcdef0"
        }
      }
    }
  ]
}
```

`ssm:SessionDocumentAccessCheck` requires a successful document access check.
Missing context fails this grant; do not remove the condition to bypass a denial.
The example narrows session permissions by region/account, uses exact system-tag
equality for cleanup, and intentionally omits resume, Run Command and IAM writes.
Policies elsewhere can add access: this Allow policy is not a permissions boundary
or an explicit denial of every other target/document. Have an administrator review
the full effective permissions, including organization and endpoint policies.

The [Session Manager sample policies](https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-restrict-access-quickstart.html)
use session-ARN scoping for OpenDataChannel. However, the
[Message Gateway authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ssmmessages.html)
states that the service does not support resource ARNs. The narrow example follows
the Session Manager guidance; its effectiveness is unverified. If channel access
is denied, retain the failure, consult AWS and validate the required caller-side
policy. Do not automatically replace it with `Resource: "*"`, add all
ssmmessages actions, or confuse agent permissions with caller permissions.

## Assumed roles and IAM Identity Center

Do not reuse the IAM-user cleanup ARN with a role: `${aws:username}` is not
available for assumed-role sessions. The
[IAM variable reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html)
explains that `${aws:userid}` includes the role ID and role session name.
An administrator must adapt session scoping for the actual identity provider.
AWS documents owner/target
[session system tags](https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-restrict-access-examples.html#restrict-access-example-4)
for federated cleanup. A role cleanup statement can use a regional/account
`session/*` ARN only when constrained by **both** exact caller identity and target
system tags; never grant unconditioned termination of all sessions. Confirm the
service's tag values in an explicitly authorized test before deployment. Missing
tags must fail closed, not cause an unconditioned fallback. Reusing a role session
name can make multiple logins share an IAM owner identity; require unique,
trusted session naming in the role/federation configuration.

IAM ownership is not process ownership: even a correctly scoped policy can permit
other sessions of the same IAM identity. `ssmh` independently retains only sessions
returned by its own StartSession call. It does not enumerate or adopt other sessions.

For explicit role assumption, the **source** identity can be allowed just:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeApprovedRemoteAccessRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/RemoteAccess"
    }
  ]
}
```

The destination role also needs a reviewed trust policy; it receives the SSM
permissions, not the source identity. See
[AssumeRole authorization](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
Require appropriate MFA/external-ID/session-name controls there. `ssmh` passes
explicit requested values without searching for alternate roles or falling back
after failure. Interactive MFA refresh is disabled after setup to protect remote
terminal input; expired credentials can therefore prevent best-effort cleanup.

## Document and future-feature permissions

For `--document SafeCommand`, replace the approved shell document ARN in both
GetDocument and StartSession grants with the reviewed command document ARN; retain
the exact target and cleanup restrictions. See [command preflight](remote-commands.md).
[AWS-owned document ARNs](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-setup-identity-based-policies.html)
have an empty account field, for example
`arn:aws:ssm:ca-central-1::document/AWS-StartNonInteractiveCommand`; do not replace
it with an account-owned ARN or authorize every document. Document administrators
remain trusted because StartSession cannot pin the preflight document version.

Every session now needs `ec2:DescribeInstances`, including explicit IDs, to verify
existence/running state before SSM; listing/check also use this read action.
This action has no resource-level
scope in the [EC2 authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html).
Listing requires this read action and ssm:DescribeInstanceInformation with Resource
"*" (both APIs lack per-instance resource scoping); narrow the selected account/
role and supported region conditions. Listing does not need StartSession or
TerminateSession. --check additionally reads the default shell document with
ssm:GetDocument and STS metadata; it never exercises StartSession permissions.
An explicit STS metadata denial is reported as unavailable using the same config,
not an authorization bypass or credential fallback. API target filters are not
IAM resource restrictions; the region condition in the example constrains the
necessary wildcard read grant. ResumeSession is not used;
add it only for a separately authorized client or
future resume feature, scoped to owned sessions. Document-owned native KMS shells/commands
also need caller kms:GenerateDataKey on the explicitly selected key and target
kms:Decrypt under its IAM/key policies. The example above intentionally grants
neither; add only the reviewed key ARN, not a wildcard. Encryption context binds
owned session/target IDs and any supplied random challenge. Forwarding
still refuses KMS. The shell-only policy above does not
authorize the implemented forwarding modes; use the separately documented fixed
forwarding-document scope for those. Never turn off required encryption or logging
to accommodate this client.

## Instance and network prerequisites

Caller permissions do not replace the agent's instance permissions. A provisioner
must install/run SSM Agent, register the instance, and supply an appropriate
[instance profile](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-instance-profile.html).
Agent/logging permissions belong to that profile, not to this caller example.
No administrator policy, iam:PassRole, inbound SSH rule or public IP is required
by the client. `ssmh` does not provision, update agents or change instance roles.

Private instances can use
[AWS PrivateLink endpoints](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-privatelink.html).
Endpoint policies, DNS, TLS trust and network rules must permit the necessary
agent/client traffic. `ssmh` will not change them or bypass certificate validation.

Ordinary SSM shells, SSH-over-SSM and port-forwarding sessions are distinct
operations. This development client implements shells and native forwarding,
not SSH tunneling; live interoperability is unverified. AWS documents that
[session content logging is unavailable for SSH and forwarding](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging.html).
CloudTrail API events are not a transcript of terminal or tunneled traffic.
Configure and verify applicable server-side logging separately; no local terminal
recording occurs by default.

## Validation before deployment

Review substitutions and complete effective permissions with your IAM administrator.
Validate the policy in IAM tooling, then test with explicitly authorized existing
resources and temporary credentials: approved versus unapproved instance/document,
channel establishment, own cleanup, and refusal to terminate another identity's
session. Do not start sessions just to simulate permission checks without approval.
Local documentation tests check JSON and intended scope only; they are not an IAM
simulator, AWS Access Analyzer result or successful live interoperability test.
