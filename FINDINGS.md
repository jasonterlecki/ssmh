# ssmh feasibility findings

Review date: 2026-10-10, against `7f98cbe` on `main`. This is a feasibility
review of the outstanding work, not a completion declaration and not new test
evidence. No AWS operation was run and no source was changed for it.

Reviewed inputs: [TODO.md](TODO.md), [PROMPT.md](PROMPT.md),
[docs/acceptance.md](docs/acceptance.md),
[docs/plugin-backend.md](docs/plugin-backend.md) and the roadmap in
[CODEX.md](CODEX.md). The repository contains no `PLAN.md`; these files were
read as the plan.

Question answered: which outstanding items cannot be accomplished? A handful
cannot be done as written. A larger group cannot be done by an agent, or on the
review machine, without the owner.

## 1. Cannot be done as written

- **Plugin: endpoint validation on resume (TODO section 6).** The official
  plugin calls ResumeSession itself and copies the replacement stream URL into
  its channel without validating it. ssmh cannot enforce its own TLS-only,
  exact-regional-host rule inside an unmodified third-party binary. The only
  reachable outcome is the checklist's "report the exact limitation" clause.
- **Plugin: safe output semantics and command status (TODO section 6).** The
  plugin writes its own banner and raw startup errors to the same stdout as
  remote output, and the project forbids classifying that stream by text
  matching. Plugin-backed `-c` therefore cannot match native's separate
  stdout/stderr and typed exit status.
- **Plugin: KMS compatibility (TODO section 6).** The reviewed plugin source
  lacks the random-context acknowledgement that newer agents can require, and
  weakening agent policy is forbidden. Unless the installed version adds it
  (not checked), this can only end as "unsupported".
- **Explaining the one-off `SSM payload digest mismatch` (TODO section 3).** No
  frames or transcript were retained, by design. Unless it recurs there is
  nothing to root-cause: "investigate" is doable, "explain" may never be.
- **Open-ended proof gates (TODO section 7; acceptance criteria 5, 9, 11).**
  "Reliability proof" and "do not substitute narrow evidence for a broader
  result" have no stopping threshold. No finite test run satisfies them; they
  need a number, such as N consecutive passes.
- **`ssmh -c "sudo -i"` as a root shell (PROMPT section 23).** The command path
  is deliberately noninteractive, so this example cannot work as described.
  The acceptance audit already concedes it.

## 2. Not possible for an agent or on the review machine

| Item | Why it is blocked |
| --- | --- |
| ARM64 runtime check | The review machine is x86_64 WSL2 with no emulator, and the checklist requires an actual ARM64 system. |
| ECS and EC2 instance-profile credentials, live | ssmh would have to run inside a task or on an instance; only the synthetic tests are available. |
| Both forwarding live tests | They need an already-running, approved echo service; an agent may not install one. |
| `TestLiveNativeCommand` and CLI `-c` live | They need an existing compatible custom document; the default AWS one is refused, and an agent may not create one. |
| Live KMS shells and commands | They need an existing key and preferences. |
| Live pagination and duplicate Names | They need an inventory that already has duplicate Name tags and more than one page (the SSM page size is 50); no tagging is allowed. |
| Least-privilege policy and the OpenDataChannel scoping conflict | Testing needs a deliberately restricted principal, which means IAM changes only the owner can make. |
| MFA refresh, AssumeRole, other partitions | They need an approved role, an MFA device, or GovCloud/China accounts. |
| Plugin logging gate | The check requires a root-owned `/usr/local/sessionmanagerplugin/seelog.xml` with one exact line. Only `seelog.xml.template` exists on the review machine, and an agent may not create the file. |
| License and release publication | These are owner decisions. |

## 3. Hard but feasible

Everything else in TODO sections 3, 4 and 7 is achievable, including the
intermittent PTY size-probe failure, although the fixed-labels-only diagnostics
rule makes each iteration slow.

The review machine already has Go 1.27.2, `govulncheck`, the AWS CLI and
`session-manager-plugin` 1.2.896.0, so the release gates are not tool-blocked
there. This is a point-in-time observation of one machine, not a portable
prerequisite.

## 4. Recommendation (owner decision, not applied)

Descope the plugin backend, all of TODO section 6. PROMPT section 2B asks for
it only "if implementing the native protocol is impractical or cannot be
validated reliably", and native already works live. Three of the plugin gates
are unmeetable as written, so the honest end state is `--backend plugin`
documented as unsupported, which is where the code is today.

Separately, give the open-ended gates in section 1 explicit exit thresholds.

Neither change has been made. TODO.md and the acceptance audit are unchanged
by this review.
