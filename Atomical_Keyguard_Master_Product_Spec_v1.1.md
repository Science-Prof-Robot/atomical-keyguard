# Atomical Keyguard

## Master Product Description and Internal Mechanics

**Specification version:** 1.1 — Skill and Living Knowledge update  
**Category:** Credential safety and capability execution for AI coding agents  
**Tagline:** **Give coding agents the keys to act—without ever giving them the keys.**

---

## 1. Executive summary

Atomical Keyguard is the credential safety layer for Claude Code, Codex, and other MCP-compatible coding agents.

Coding agents can already inspect repositories, write code, run tests, and invoke developer tools. The dangerous gap appears when the agent needs a real credential: a Cloudflare API token, GitHub token, database password, Stripe key, AWS role, npm token, or production deployment secret.

Today, developers usually solve this by placing secrets in `.env` files, exporting them into a terminal, pasting them into an agent conversation, or granting a coding agent broad shell access. Each approach collapses the security boundary between **reasoning** and **authority**.

Atomical Keyguard changes the model:

- **Atomical gives the agent a verifiable identity.**
- **Atomical Deposit Box provides one-time secret handoff.**
- **Atomical Vault or Keyguard’s sealed hosted-mode store protects credentials at rest.**
- **Atomical request signing proves which agent requested an action.**
- **Keyguard turns credentials into narrow capabilities, policies, approvals, and signed execution receipts.**
- **Claude Code and Codex receive only explicitly installed actions, never a tool to read a credential.**
- **An installable Atomical Keyguard skill carries safe deployment know-how, Atomical documentation, project runbooks, and sanitized operational memory into every supported coding environment.**

The model never needs to see the raw credential. It asks Keyguard to perform an approved operation. Keyguard retrieves the credential behind the boundary, executes a predefined provider action, strips sensitive output, and returns only the result.

Keyguard itself is vendor-neutral. A new Keyguard profile contains an empty
action registry: no cloud provider, deployment target, or credential mapping is
assumed. A provider-specific action exists only when a maintainer deliberately
installs a reviewed adapter. Cloudflare Pages may be used as a reference adapter,
but is never the product default.

Atomical is not a logo added to the product. It is the product’s identity, trust, and memory-provenance substrate.

The complete product therefore has three deliberately separate layers:

1. **Atomical trust layer** — identity, Deposit Box, Vault, signing, and verifiable provenance.
2. **Keyguard execution layer** — policies, approvals, provider adapters, redaction, and receipts.
3. **Keyguard skill layer** — installation, deployment guidance, provider runbooks, project-specific memory, and error learning for Claude Code and Codex.

---

## 2. Product name

# **Atomical Keyguard**

### Supporting line

**The credential firewall for coding agents.**

### Why the name works

- **Atomical** makes the underlying identity, vault, deposit, and signing system explicit.
- **Keyguard** communicates credential safety without sounding like a generic password manager.
- The product can be described naturally: “Install Atomical Keyguard in Codex,” “approve the Keyguard request,” or “run the deployment through Keyguard.”

Other considered names:

- Atomical SafeKey
- Atomical CredGuard
- Atomical Seal
- Atomical Keychain
- Atomical VaultGate

Atomical Keyguard is the strongest combination of clarity, defensibility, and brand value.

---

## 3. Product thesis

The next generation of software agents should not possess reusable secrets.

They should possess:

1. **Identity** — who is requesting the operation?
2. **Intent** — what exact action is being requested?
3. **Policy** — is this agent allowed to perform that action here?
4. **Approval** — does a human need to authorize this instance?
5. **Capability** — a narrow operation, rather than unrestricted credential access.
6. **Proof** — a signed, inspectable receipt of what happened.

Atomical supplies the domain-bound identity and cryptographic trust primitives. Keyguard adds the execution boundary that coding environments need.

---

## 4. The problem

A coding agent often needs external authority to finish useful work:

- deploy a web application
- publish a package
- create or merge a pull request
- access a production database
- run a migration
- read an error-monitoring project
- update cloud infrastructure
- trigger a CI pipeline
- create a release
- upload an artifact
- call a billing or payments API

The obvious implementation is to expose an environment variable or secret-reading tool. That creates several risks:

### Prompt-injection exfiltration

A malicious README, issue, dependency, webpage, or tool response can tell the agent to print environment variables or send credentials elsewhere.

### Excessive authority

A general API token may permit far more than the requested operation.

### Untraceable usage

Teams can see that a key exists, but not which agent used it, for what purpose, against which resource, and with which code revision.

### Secret persistence

Credentials leak into shell history, transcripts, logs, crash dumps, `.env` files, generated code, or agent memory.

### Shared identity

Multiple agents use the same human-owned token, making attribution and revocation difficult.

---

## 5. The Atomical foundation

Atomical Keyguard is built around five Atomical concepts.

### 5.1 Agent identity

Every Keyguard-enabled coding agent receives an Atomical identity such as:

```text
builder.atomic.bond
deploy-agent.company.com
release-bot.company.com
```

Atomical binds the identity to:

- a domain
- an Ed25519 keypair
- a public `/.well-known/agent.json` identity document

The private key remains with the runtime. Services can fetch `agent.json` and verify that a signed request came from the identified agent.

### 5.2 Deposit Box

A user or another agent should never paste a credential into a coding conversation.

Keyguard asks Atomical for a one-time, expiring Deposit Box URL:

```bash
atomic deposit-url --label <installed-action-credential-label> --expires 10m
```

The user opens the URL and deposits the credential. The link is scoped to a label, signed, time-limited, and single-use.

This becomes Keyguard’s preferred “Add credential” flow.

### 5.3 Vault

In local Atomical mode, Keyguard delegates credential storage to the Atomical Vault:

```bash
atomic vault set <label> <secret>
atomic vault list
atomic vault delete <label>
```

Keyguard never creates a parallel plaintext `.env` file.

In hosted Atomical mode, the public documentation describes deposits being forwarded to a configured webhook. Keyguard receives that signed event, immediately seals the secret in its local runtime store, and discards the webhook payload. The hosted webhook boundary must be treated as a sensitive plaintext handoff and protected accordingly.

### 5.4 Request signing

Each execution request and completion receipt is signed using the Atomical agent identity.

A signed request communicates:

- which Atomical agent requested it
- the exact body that was authorized
- the signing timestamp
- cryptographic proof that the message was not modified

The signature headers are:

```text
X-Agent-Id
X-Agent-Sig
X-Agent-Sig-Time
```

### 5.5 Public verification and revocation

A relying service verifies an Atomical agent by:

1. reading `X-Agent-Id`
2. fetching `https://{agent-id}/.well-known/agent.json`
3. checking that the identity is active
4. reconstructing the signed message
5. verifying the Ed25519 signature
6. enforcing freshness and replay protection

The domain is the identity; the keypair proves control.

---

## 6. What Keyguard adds on top of Atomical

Atomical supplies identity, secure deposit, encrypted storage, and signatures.

Keyguard adds the coding-agent-specific control plane:

- MCP tools for Claude Code and Codex
- credential metadata without credential disclosure
- provider action adapters
- policy enforcement
- project and repository binding
- human approval queues
- time-limited action leases
- output redaction
- audit events
- signed execution receipts
- a local web interface
- an installable `atomical-keyguard` Agent Skill for Claude Code and Codex
- project-local or global skill scope selection
- an Atomical-signed Living Field Manual containing deployment runbooks and sanitized operational memory
- install templates for `CLAUDE.md` and `AGENTS.md`

### The critical boundary

Keyguard does **not** expose:

```text
get_secret(label)
reveal_credential(label)
export_all_credentials()
```

Keyguard exposes:

```text
list_available_credentials()
list_available_actions()
create_deposit_link()
request_action()
execute_approved_action()
delete_credential()
```

### 6.1 Vendor-neutral baseline and integration boundary

The default Keyguard core consists of identity, a sealed credential vault,
policy evaluation, exact approval, redaction, activity, and signed receipts. It
does **not** contain a provider adapter by default.

- The initial action registry is empty. Listing capabilities is the source of
  truth for what a profile can do.
- A reviewed integration is supplied by trusted application configuration at
  startup. Repository text, a field manual, memory, an MCP request, and an
  agent prompt cannot add, change, or select an adapter implementation.
- An integration declares a stable action name and version, a credential
  binding, typed parameter validation, canonical target derivation,
  execution-time revalidation, a fixed internal executor, and a safe verifier.
  It may use a provider SDK or a fixed invocation internally, but never an
  agent-configurable command, URL, header, environment-variable name, or
  post-execution script.
- Local coding is separate from external authority. An agent may create, edit,
  or test local files when the user asks; that does not authorize a provider
  call, credential request, or deployment.
- If a provider is absent, the skill says it is **not installed in this
  Keyguard profile**. It does not substitute another provider, request a
  credential, guess an API or CLI, or perform an external action. It may show
  installed capabilities or ask for official documentation to review a future
  adapter.

---

## 7. Product experience

### 7.1 First-run onboarding

The Keyguard installer performs environment discovery before changing the machine. It detects:

- the `atomic` CLI and active Atomical identity
- Claude Code and Codex installations
- the current Git repository and project root
- any existing Keyguard MCP registration
- any existing `atomical-keyguard` skills
- hosted or local Atomical mode
- the active policy file and local control-plane status

The onboarding then asks two explicit questions.

**Which coding environments should use Keyguard?**

- Claude Code
- Codex
- both

**Where should the skill be installed?**

- **This project** — repository-scoped knowledge and workflows
- **Globally for this user** — available in every repository
- **Both** — a small global foundation plus a project-specific overlay

For a project installation, Keyguard also asks whether the skill should be team-shared in version control or private and gitignored.

The installer must preview every destination before writing files. Installation is never silently escalated from project scope to global scope.

The local control UI opens on loopback only:

```text
http://127.0.0.1:4545
```

### 7.2 Identity setup

Recommended hackathon flow:

```bash
atomic init --hosted --name keyguard-builder
atomic config set webhook-url https://<tunnel>/atomic/events
```

Recommended developer-machine production flow:

- use an Atomical identity on a controlled domain or local/self-hosted Atomical runtime
- keep the Atomical private key outside the repository
- use Atomical Vault for local credential storage

### 7.3 Adding a credential

The user clicks **Add credential**.

The UI asks for:

- label
- provider
- environment
- description
- allowed actions
- expiry or rotation date
- approval mode

The recommended action is **Generate Atomical Deposit Link**.

Keyguard runs:

```bash
atomic deposit-url --label <installed-action-credential-label> --expires 10m
```

The user deposits the secret into Atomical. The coding agent never sees the value.

For an offline local demo, Keyguard can also accept a credential directly over `127.0.0.1` and immediately seal it. The UI clearly labels this as a fallback, not the preferred Atomical flow.

### 7.4 Agent requests an action

After a reviewed adapter has been explicitly installed, the agent can call its
listed action. For example:

```text
execute_action(
  action="publish_site",
  params={
    "directory": "dist",
    "site": "keyguard-demo"
  }
)
```

Keyguard computes an action envelope:

```json
{
  "agent": "keyguard-builder.atomic.bond",
  "action": "publish_site",
  "action_version": 1,
  "credential_label": "site-publish-token",
  "project_root": "/repo/keyguard-demo",
  "git_commit": "81f4ac2",
  "params": {
    "directory": "dist",
    "site": "keyguard-demo"
  },
  "requested_at": "2026-07-14T10:44:00Z"
}
```

### 7.5 Policy evaluation

The policy engine checks:

- Is the Atomical identity active?
- Is the credential present?
- Is the action allowlisted?
- Is this repository allowed?
- Is the target environment allowed?
- Are the parameters valid?
- Is the requested path inside the repository?
- Is an approval required?
- Has the request expired?
- Was this request already consumed?
- Is the action within rate, cost, and time limits?

### 7.6 Human approval

For risky actions, Keyguard returns:

```json
{
  "status": "approval_required",
  "request_id": "apr_7N4M2",
  "message": "Approve in Atomical Keyguard."
}
```

The UI displays:

- agent identity
- repository and commit
- requested action
- provider
- destination
- credential label, never value
- exact normalized target and scope
- expected side effects
- expiry countdown

The user can approve once, deny, or approve an exact repeatable scope.

### 7.7 Execution

Keyguard executes a predefined provider adapter.

The credential is injected only into the adapter subprocess or provider SDK:

```text
Agent model context
        │
        │ action + parameters
        ▼
Keyguard policy boundary
        │
        │ retrieves secret internally
        ▼
Provider executor
        │
        │ API request / child process environment
        ▼
External service
```

The secret must not be:

- returned through MCP
- interpolated into a shell string
- persisted in logs
- written into repository files
- included in error traces
- shown in the UI
- stored in agent memory

### 7.8 Signed receipt

After execution, Keyguard creates a receipt:

```json
{
  "receipt_id": "rcpt_V9H8K",
  "atomical_agent": "keyguard-builder.atomic.bond",
  "action": "publish_site",
  "action_version": 1,
  "credential_label": "site-publish-token",
  "repository": "keyguard-demo",
  "git_commit": "81f4ac2",
  "target": "keyguard-demo.example-provider.dev",
  "exit_code": 0,
  "started_at": "2026-07-14T10:45:10Z",
  "completed_at": "2026-07-14T10:45:31Z",
  "secret_exposed_to_model": false
}
```

The canonical JSON body is signed using Atomical. The receipt includes or references the Atomical signature headers.

### 7.9 Skill-assisted deployment

The user can invoke the Keyguard workflow directly from the coding environment.

- In Claude Code, the project or personal skill appears as `/atomical-keyguard`.
- In Codex, the same Agent Skill appears in the Skills picker and is explicitly invoked as `$atomical-keyguard`; product copy may call this the Atomical Keyguard command while preserving the host-native invocation syntax.

The skill supports intent-oriented entry points such as setup, status, add credential, deploy, diagnose, memory, rotate, and revoke. It does not implement the privileged action itself. It guides the agent to the correct Keyguard MCP capability and explains what approval or Atomical deposit is required.

### 7.10 Learning after the operation

After a verified deployment or resolved failure, the skill proposes or records a sanitized learning:

- the successful build and deployment sequence
- the provider action and non-secret credential label used
- the exact validation that proved success
- a normalized error fingerprint and verified resolution
- an explicit user instruction such as “always deploy this service from `apps/web`”

The learning is scoped to the project by default. Global promotion requires explicit user approval unless it is a signed upstream documentation update.

---

## 8. System architecture

The adapter branch is optional: a default Keyguard profile has no provider
adapter. Examples below are categories of a reviewed adapter supplied at
startup, not built-in services.

```text
┌─────────────────────────────────────────────────────────┐
│ Claude Code / Codex                                     │
│                                                         │
│ Atomical Keyguard Skill                                 │
│ workflow · docs · runbooks · sanitized project memory   │
└───────────────────────┬─────────────────────────────────┘
                        │ invokes named capabilities
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Atomical Keyguard MCP Server                            │
│                                                         │
│ list labels · deposit link · request action · receipts  │
│ no raw secret-reading interface                         │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Keyguard Policy and Approval Engine                     │
│                                                         │
│ action allowlist · path scope · TTL · replay protection │
│ human approval · rate/cost limits                       │
└───────────────┬───────────────────────┬─────────────────┘
                │                       │
                ▼                       ▼
┌──────────────────────────┐  ┌───────────────────────────┐
│ Atomical trust substrate │  │ Provider action adapters  │
│                          │  │                           │
│ identity + agent.json    │  │ none by default           │
│ Deposit Box              │  │ reviewed adapter only     │
│ Vault                    │  │ site publish · release    │
│ Ed25519 request signing  │  │ configure at startup      │
└───────────────┬──────────┘  └───────────────┬───────────┘
                │                              │
                ▼                              ▼
┌──────────────────────────┐  ┌───────────────────────────┐
│ Local Keyguard UI        │  │ Installed provider         │
│ install + credentials    │  │ receives scoped operation │
│ approvals + memory       │  │                           │
│ audit + receipts         │  │                           │
└──────────────────────────┘  └───────────────────────────┘
```

---

## 9. Components

### 9.1 Keyguard daemon

A loopback-only local service responsible for:

- Atomical CLI and SDK integration
- signed webhook intake
- credential storage adapter
- policy evaluation
- approvals
- provider execution
- audit logging
- UI API

### 9.2 MCP server

A stdio MCP server installed into Claude Code and Codex.

It exposes a deliberately small tool surface:

- `keyguard_status`
- `list_credentials`
- `list_actions`
- `create_deposit_link`
- `execute_action`
- `delete_credential`

Destructive credential deletion should require explicit human approval in the full product. The starter keeps it visible for demonstration.

### 9.3 Atomical Keyguard Skill Manager

The Skill Manager owns installation and lifecycle management for the shared Agent Skill used by Claude Code and Codex.

Responsibilities:

- detect supported coding environments
- ask for project, global, or combined scope
- create the correct host-native skill locations
- maintain a canonical shared skill bundle where possible
- register the Keyguard MCP dependency
- verify that the active Atomical identity is reachable
- install the project guidance shim without duplicating large instructions
- manage the Living Field Manual and memory ledger
- show upstream skill and documentation updates
- preserve user and project memory across core skill upgrades
- remove or disable the skill cleanly without deleting credentials

The Skill Manager must treat install scope as a security decision. A repository must never be allowed to silently install or modify a global user skill.

### 9.4 Credential Control UI

A local HTML interface with four areas:

1. **Identity** — active Atomical identity and status
2. **Credentials** — labels, providers, dates, allowed actions
3. **Approvals** — pending action requests
4. **Activity** — append-only, secret-free audit events

### 9.5 Storage adapter

Two supported modes:

#### `atomical-local`

- delegates set, list, get, and delete to Atomical Vault
- strongest fit for developer machines
- raw values are only read by the executor process

#### `sealed-local`

- used for hosted Atomical webhook delivery
- AES-256-GCM encrypted local store
- master key held outside the repository with `0600` permissions
- intended as the bridge between Atomical hosted deposits and local execution

### 9.6 Provider adapters

Provider adapters are optional, reviewed integrations—not product defaults. The
default registry is empty. Each installed adapter defines:

- stable action name and adapter version
- credential label and provider binding
- permitted parameters, validators, and canonical target derivation
- a fixed internal executor (provider SDK or fixed invocation)
- execution-time revalidation, output redaction, approval policy, timeout, and
  safe verification behavior
- an explicitly bounded project scope

Keyguard signs the full credential binding (label and provider), checks it
against the installed adapter and sealed credential metadata, and re-runs the
adapter's canonical target preparation immediately before secret access and
again immediately before launch. A changed binding or target fails closed.

No action is generated dynamically by the model. No wildcard project scope,
command/argument template, HTTP template, credential binding, or adapter can be
supplied by an agent, repository, field manual, or request payload. A Cloudflare
Pages adapter is an optional reference integration only; it is installed
explicitly when a deployment needs it.

---

## 10. Atomical Keyguard Skill and Living Knowledge Layer

### 10.1 Purpose

The Atomical Keyguard Skill is the user-facing operational brain of the product.

The MCP server knows **what actions exist** and enforces their boundaries. The skill knows **how and when to use those actions safely**. Atomical establishes **which agent is acting**, how credentials enter, and how resulting knowledge can be signed and attributed.

The skill is based on the open Agent Skills format so one conceptual bundle can serve both Claude Code and Codex while using each host’s native discovery rules.

### 10.2 Native invocation model

| Environment | Direct invocation | Project scope | Global user scope |
|---|---|---|---|
| Claude Code | `/atomical-keyguard` | `.claude/skills/atomical-keyguard/` | `~/.claude/skills/atomical-keyguard/` |
| Codex | `$atomical-keyguard` or Skills picker | `.agents/skills/atomical-keyguard/` | `$HOME/.agents/skills/atomical-keyguard/` |

The product should present a unified **Atomical Keyguard skill** rather than pretending the two hosts have identical command syntax. In UI copy, “Invoke Atomical Keyguard” is the portable action; the UI shows the exact native command for the detected host.

The skill may also activate implicitly when the user asks to deploy, publish, rotate credentials, configure a provider, or diagnose a Keyguard-mediated failure. Destructive operations should still require explicit confirmation and Keyguard policy approval.

### 10.3 Installation and scope selection

Keyguard installation is a guided transaction with a reviewable plan.

The installer presents:

1. detected environments
2. current Atomical identity
3. MCP registration status
4. proposed skill destination
5. selected memory scope
6. whether files will be committed or private
7. any permissions or trust prompts the host will show

Scope choices:

#### This project

Use for repository-specific deployment procedures, provider mappings, service topology, and known errors.

- Claude Code receives the skill under `.claude/skills/atomical-keyguard/`.
- Codex receives the skill under `.agents/skills/atomical-keyguard/`.
- A shared canonical knowledge directory may live under `.atomical/keyguard/` so both host adapters read the same runbooks and memory without diverging.
- The user chooses whether the project package is committed for the team or kept private and gitignored.

#### Global for this user

Use for general Atomical concepts, universal safety rules, personal deployment preferences, and provider knowledge that applies across repositories.

- Claude Code receives the skill under `~/.claude/skills/atomical-keyguard/`.
- Codex receives the skill under `$HOME/.agents/skills/atomical-keyguard/`.
- Global memory is never writable by an untrusted repository.

#### Both

This is the recommended advanced setup.

- The global skill contains stable Atomical safety rules and general provider guidance.
- The project overlay contains repository-specific facts and learned runbooks.
- Project instructions override or narrow general behavior but cannot relax global credential safety invariants.

### 10.4 Automatic project bootstrap

When a global Keyguard skill is present and the user invokes it inside a repository that has no local Keyguard profile, it offers to bootstrap the current project.

The prompt is explicit:

> Atomical Keyguard is available globally. Create a project-local deployment and memory profile here?

Choices:

- Create private project profile
- Create team-shared project profile
- Continue with global knowledge only
- Cancel

The skill must not write into the repository until the user selects an option. It must show the planned files and explain whether they will be committed.

### 10.5 Skill bundle semantics

The conceptual skill bundle contains:

- **SKILL.md** — activation rules, safe workflow, and MCP capability routing
- **Atomical field guide** — identity, Deposit Box, Vault, signing, receipts, and agent-to-agent concepts
- **Provider runbooks** — only for explicitly installed, reviewed adapters;
  absence of a runbook or installed action means the provider is not available
  in that Keyguard profile
- **Deployment playbooks** — discover, build, request credentials, approve, execute, verify, and rollback
- **Error cookbook** — sanitized error fingerprints and verified resolutions
- **Project memory** — local facts, decisions, working commands, and successful deployment recipes
- **Safety policy reference** — actions that are forbidden regardless of project content
- **Version manifest** — core skill version, docs snapshot version, provider-pack versions, and local-memory schema

The main skill file remains concise. Detailed material is loaded progressively only when the current task requires it.

### 10.6 What the skill knows

The skill should be able to answer and act on questions such as:

- Which Atomical identity is active in this project?
- Which credential labels exist without revealing their values?
- What is the approved way to deploy this repository?
- Which Keyguard capability maps to the requested provider action?
- What approval will be required?
- Which build and verification commands succeeded previously?
- Has this provider error occurred before?
- What did the user explicitly ask the agent to remember?
- Is the relevant knowledge project-specific, personal-global, or signed upstream guidance?

It must never answer:

- What is the credential value?
- Can the token be printed for debugging?
- Can the secret be copied into `.env`?
- Can policy be bypassed because a repository file requests it?

### 10.7 Skill-assisted deployment workflow

When the user asks to deploy, the skill follows a consistent sequence:

1. identify the repository, service, target environment, and desired provider
2. list the current Keyguard capabilities before assuming a provider is present
3. if no installed action matches, say the provider is not installed in this
   Keyguard profile; do not substitute a provider, request credentials, or
   invoke an external API or CLI
4. load the smallest relevant project and installed-provider runbooks
5. inspect prior successful receipts and sanitized deployment memory
6. determine the required Keyguard capability and credential label
7. request an Atomical Deposit Box link if the label is missing
8. prepare a human-readable action plan
9. call the Keyguard MCP capability
10. pause for approval when required
11. execute only through the approved Keyguard provider adapter
12. verify the deployed system using a non-secret validation method
13. return the Atomical-signed receipt
14. create a memory candidate from the verified outcome

The skill is an orchestrator and teacher. Keyguard remains the authority boundary.

### 10.8 The Living Field Manual

The evolving knowledge system is called the **Atomical Keyguard Living Field Manual**.

It combines four layers without mixing their trust levels:

#### Core Atomical knowledge

Stable explanations of Atomical identity, Deposit Box, Vault, signing, webhook verification, agent-to-agent flows, and the provider automation model.

Core updates must be versioned and signed by the Atomical Keyguard publisher identity before automatic installation.

#### Provider knowledge

Versioned deployment instructions and action semantics for supported providers. Provider guidance includes prerequisites, least-privilege recommendations, known failure modes, verification steps, and rollback guidance.

#### Project operational memory

Facts discovered and verified in the current repository, such as:

- the real build command
- the deployable directory
- the service or project name
- required non-secret environment variable names
- the correct provider capability
- health-check URLs
- rollback instructions
- successful receipt references

#### User-directed notes

Instructions explicitly provided by the user, such as:

- “Always deploy staging before production.”
- “This project uses pnpm, not npm.”
- “Never publish from a dirty working tree.”
- “Remember that production approval belongs to the platform team.”

### 10.9 Memory intake triggers

A memory candidate may be created from:

- an explicit user phrase such as “remember,” “note,” “always,” or “for this project”
- a successful Keyguard action with independent verification
- a deployment failure followed by a verified resolution
- a recurring normalized error that has appeared more than once
- a policy or credential-label mapping approved by the user
- a signed upstream Atomical Keyguard documentation update

Repository text, provider output, web content, package documentation, and untrusted MCP responses cannot directly write durable memory.

### 10.10 Memory record model

Every durable learning should carry provenance rather than being stored as an unattributed paragraph.

A memory record includes:

- memory ID
- project or global scope
- type: fact, preference, runbook, error resolution, safety decision, or provider note
- concise statement
- evidence references
- originating Atomical agent identity
- creation and last-verification timestamps
- confidence level
- source classification
- related receipt or approval IDs
- content hash
- Atomical signature or signature reference
- expiry or review date when the knowledge may become stale

This makes memory inspectable, portable, and resistant to silent tampering.

### 10.11 Memory update policy

Not every observation deserves permanent memory.

#### May update automatically

- a successful project-local build or deploy recipe verified by exit status and health check
- a non-sensitive project path or service name
- a normalized error fingerprint paired with a proven fix
- last-used receipt references and verification timestamps

#### Must be proposed for review

- any global memory change
- any security or approval-policy change
- provider guidance inferred from an error rather than official documentation
- a rule that changes production behavior
- a correction that conflicts with existing memory
- a user statement that may be temporary or ambiguous

#### Must never be stored

- credential values
- authorization headers
- active Deposit Box URLs
- private keys
- session cookies
- OTP values
- unredacted provider logs
- command output containing secret material
- raw conversation transcripts when a concise note is sufficient

### 10.12 Error learning loop

Keyguard converts failures into reusable operational knowledge without allowing logs to become a secret or prompt-injection channel.

The error loop is:

1. capture a bounded, redacted error
2. normalize volatile fields such as timestamps, IDs, paths, and request numbers
3. fingerprint the stable error pattern
4. search project and provider memory for a match
5. apply a known resolution only through allowed tools
6. verify that the error is resolved
7. record the resolution, evidence, and environment
8. reduce confidence if the solution later fails

An error is not considered “learned” merely because the model suggested a fix. It becomes durable only after verification or explicit user confirmation.

### 10.13 User-directed memory experience

When the user says something important, the skill responds with a compact scope decision rather than silently writing everywhere.

Example:

> Remember that production deployments for this repository must use the `release` branch.

Keyguard interprets this as a project safety rule and confirms:

> Save to this project’s Atomical Keyguard memory? This will apply to Claude Code and Codex in this repository. It will not be stored globally.

For obviously local and non-sensitive facts, the product may support an “always save project notes automatically” preference. Global memory and security rules always remain reviewable.

### 10.14 Documentation updates

The skill separates immutable upstream content from mutable local knowledge.

- Core skill and Atomical docs snapshots are versioned.
- Updates are checked on a bounded cadence rather than on every prompt.
- The UI shows current and available versions.
- Upstream packages are verified against a publisher identity or trusted release channel.
- Local project memory is preserved during upgrades.
- Upstream updates cannot overwrite explicit user rules silently.
- Conflicts produce a review card showing old guidance, new guidance, and affected workflows.

The long-term distribution model may package the skill, MCP dependency, hooks, and visual metadata as installable plugins, but direct project and user skill folders remain the minimum portable implementation.

### 10.15 Skill, hooks, and memory boundaries

The skill contains guidance and may choose the right workflow. It is not a deterministic enforcement mechanism.

Use:

- **Skill instructions** for deployment reasoning, provider know-how, and choosing Keyguard tools
- **MCP** for protected actions and shared runtime state
- **Hooks** for deterministic checks such as secret scanning, post-action memory-candidate creation, and instruction-load auditing
- **Project guidance files** for a small set of rules that must always be present
- **Keyguard policy** for non-bypassable action restrictions

Host-native auto memory may complement Keyguard memory, but Keyguard must keep its own explicit, inspectable memory ledger because credential operations require stronger provenance and scope controls than general assistant memory.

### 10.16 Atomical as the memory provenance layer

Atomical makes the Living Field Manual meaningfully different from a folder of agent notes.

- The active Atomical identity attributes every learned operational fact to a specific agent.
- Signed memory entries allow another runtime to verify who recorded the learning and whether it changed.
- Agent-to-agent transfer can carry a sanitized runbook without transferring the underlying credential.
- A project can trust knowledge signed by approved Atomical identities while rejecting unsigned memory patches.
- Revocation of an Atomical identity can mark its unreviewed memories as untrusted without deleting historical receipts.

The product promise becomes:

> One Atomical identity, one credential boundary, and one continuous operational memory across coding environments.

### 10.17 Skill status and maintenance commands

The skill should conceptually support:

- **setup** — install or repair host integration
- **status** — show Atomical identity, MCP, credential labels, policies, and skill versions
- **add** — create an Atomical Deposit Box flow
- **deploy** — run the safe deployment workflow
- **doctor** — diagnose identity, MCP, policy, provider, and memory issues
- **memory** — inspect, approve, edit, promote, or forget learnings
- **update** — review core skill, documentation, and provider-pack updates
- **rotate** — guide credential rotation without revealing values
- **revoke** — disable a credential, capability, agent identity, or memory trust source

These are workflow intents, not direct secret-handling commands.

---

## 11. Credential model

```json
{
  "label": "site-publish-token",
  "provider": "example-provider",
  "environment": "production",
  "description": "Publish site keyguard-demo",
  "storage": "atomical-local",
  "created_at": "2026-07-14T09:30:00Z",
  "expires_at": null,
  "rotation_due_at": "2026-10-14T00:00:00Z",
  "allowed_actions": [
    "publish_site"
  ],
  "allowed_projects": [
    "/Users/ashish/projects/keyguard-demo"
  ],
  "approval": "every_write",
  "status": "active"
}
```

This is an illustrative metadata record for an explicitly installed adapter; it
does not create a provider capability. The metadata may be listed to the coding
agent. The credential value may not.

---

## 12. Policy model

```json
{
  "actions": {}
}
```

The default policy contains no provider action. A reviewed startup integration
may add a narrow action such as `publish_site`, but its credential binding,
typed validation, target derivation, fixed executor, and verifier live in
trusted adapter code rather than in model-editable JSON. It must use explicitly
configured project roots; `*` is never valid. The field manual and an agent may
describe an installed action, but cannot add or mutate one.

### Parameter types

Initial validators should include:

- `slug`
- `relative_path`
- `https_url`
- `git_ref`
- `semver`
- `enum`
- `integer_range`

Relative paths must be normalized and rejected if they escape the project root.

---

## 13. Security invariants

### Invariant 1: no secret-reading interface

Neither MCP nor HTTP provides a reveal endpoint.

### Invariant 2: no arbitrary shell

The model selects an action and supplies validated parameters. It cannot supply the executable.

### Invariant 3: credentials are attached to actions

Credentials are not globally available to every action.

### Invariant 4: model-visible output is scrubbed

Executor stdout and stderr are checked against the secret value and common encodings before being returned.

### Invariant 5: requests are identity-bound

Action envelopes and receipts are signed with the Atomical identity.

### Invariant 6: approvals are exact and expiring

An approval applies to one request body, one project revision, and a short time window.

### Invariant 7: the UI is local by default

The control UI binds to `127.0.0.1`, not `0.0.0.0`.

### Invariant 8: no secrets in audit records

Audits contain labels and hashes, not values.

### Invariant 9: prompt content cannot alter policy

Repository text, model instructions, and tool output cannot add an action or change its credential mapping.

### Invariant 10: destructive actions are harder than read actions

Production writes, publishing, deletion, and payments require stronger approval.

---

## 14. Threat model

### Prompt injection

**Attack:** a repository file instructs the model to print keys.

**Defense:** no `get_secret` tool exists; action adapters do not return credentials.

### Arbitrary-command abuse

**Attack:** the model asks Keyguard to execute `env` or upload a secret.

**Defense:** fixed executable and argument templates; typed parameters; no shell interpolation.

### Path traversal

**Attack:** an action references `../../private`.

**Defense:** canonicalize and enforce project-root containment.

### Replay

**Attack:** reuse a previously approved request.

**Defense:** request ID, nonce, body hash, expiry, and consumed status.

### Fake webhook

**Attack:** an attacker sends a fabricated `deposit.received` event.

**Defense:** verify Atomical signature headers against the public key in `agent.json`, check timestamp freshness, and optionally require a second webhook token.

### Malicious provider output

**Attack:** external output includes prompt injection or reflects a secret.

**Defense:** structured provider adapters, output size limits, redaction, and treating output as untrusted data.

### Compromised coding agent

**Attack:** the coding agent intentionally attempts exfiltration.

**Defense:** capability-only execution reduces exposure, but cannot make an overly broad provider token safe. Use least-privilege provider credentials and provider-side restrictions.

### Local-machine compromise

**Attack:** malware can read process memory or user files.

**Defense:** Keyguard is not a replacement for endpoint security. Use OS keychains, hardware-backed keys, isolated execution, and short-lived provider credentials in production.

---

## 15. Claude Code installation

Claude Code supports personal skills available across projects and project skills available only within a repository. The directory name becomes the slash command, so an `atomical-keyguard` skill is invoked as `/atomical-keyguard`.

### Recommended installer experience

The Keyguard installer detects Claude Code and asks:

> Install Atomical Keyguard for this project or globally for your user?

#### Project scope

Destination:

```text
<repo>/.claude/skills/atomical-keyguard/
```

Use this scope for repository-specific deployment knowledge. The installer asks whether the directory should be committed for the team or kept private.

#### Global scope

Destination:

```text
~/.claude/skills/atomical-keyguard/
```

Use this scope for universal Atomical safety rules and cross-project provider knowledge.

#### Combined scope

Install the stable foundation globally and a smaller project overlay locally. The project overlay can add or narrow deployment guidance but cannot weaken the global no-secret-exposure rules.

### MCP pairing

The installer registers the Atomical Keyguard MCP server and verifies it separately from the skill. The skill explains the workflow; MCP exposes the capabilities.

### Project guidance

Keyguard should add only a compact project guidance shim to `CLAUDE.md` or `CLAUDE.local.md`, directing Claude to the skill and stating the non-negotiable secret rules. Detailed runbooks remain inside the progressively loaded skill.

### Verification

The onboarding asks the user to open Claude Code and invoke:

```text
/atomical-keyguard status
```

A successful check reports the Atomical identity, skill scope, MCP status, policy version, and memory version without showing any credential value.

---

## 16. Codex installation

Codex uses the same Agent Skills format with repository skills under `.agents/skills` and user skills under `$HOME/.agents/skills`.

### Recommended installer experience

The Keyguard installer detects Codex and asks the same project/global scope question.

#### Project scope

Destination:

```text
<repo>/.agents/skills/atomical-keyguard/
```

#### Global scope

Destination:

```text
$HOME/.agents/skills/atomical-keyguard/
```

#### Combined scope

Use global safety and provider guidance with a project-local operational overlay.

### Native invocation

Codex users invoke the skill through the Skills picker or by mentioning:

```text
$atomical-keyguard
```

The product should not falsely claim that Codex and Claude Code use identical command syntax. The unified product concept is the **Atomical Keyguard skill**; each adapter displays the host-native invocation.

### MCP pairing

The installer registers the same Atomical Keyguard MCP server for Codex. The skill may declare the MCP dependency in its host metadata so the UI can show whether the required tool is available.

### Project guidance

A concise `AGENTS.md` block establishes permanent repository safety rules and points Codex to the skill. The evolving deployment knowledge remains in the skill’s references and Keyguard memory ledger.

### Verification

The onboarding directs the user to select or invoke Atomical Keyguard and run its status workflow. The result should match the Claude Code status output semantically.

---

## 17. Atomical setup

### Hosted identity for a fast demo

```bash
atomic init --hosted --name keyguard-builder
atomic whoami
```

Expose the local webhook with a trusted tunnel and configure:

```bash
atomic config set webhook-url https://<your-tunnel>/atomic/events
```

Inject the hosted private key only into the Keyguard daemon or MCP process:

```bash
export ATOMIC_PRIVATE_KEY="<base64-ed25519-private-key>"
export ATOMIC_DOMAIN="keyguard-builder.atomic.bond"
```

### Local Atomical vault mode

Initialize Atomical on a controlled domain or local server, then select:

```bash
export KEYGUARD_STORAGE=atomical-local
```

Keyguard will delegate credential storage to `atomic vault`.

---

## 18. Atomical-native micro UI design semantics

The Keyguard control plane should feel like a direct extension of Atomical, not a generic password manager or cloud admin dashboard.

### 18.1 Brand principles

The visual system should communicate:

- **one identity** rather than many disconnected integrations
- **continuous memory** rather than disposable setup screens
- **signed actions** rather than opaque automation
- **calm authority** rather than security theatre
- **agent independence** rather than a human account being impersonated

The UI should borrow Atomical’s product language: `whoami`, domain identity, `signed`, `memory · continuous`, channel/resource rows, and the Atomical seal.

### 18.2 Visual language

- Use a near-black or deeply neutral canvas with generous negative space.
- Use warm off-white text and one restrained high-contrast Atomical accent sourced from the current brand token rather than inventing multiple product colors.
- Pair a clean editorial sans-serif for headlines with a monospaced face for identities, hashes, labels, timestamps, commands, and signatures.
- Prefer hairline dividers, flat surfaces, and subtle depth over glossy cards and dashboard chrome.
- Use lowercase product language where it strengthens the Atomical feel: `atomical keyguard`, `whoami`, `signed`, `sealed`, `memory`.
- Use directional glyphs such as `▸`, middle dots, and short terminal-like status rows.
- Avoid shield clichés, padlock illustrations, neon cyberpunk effects, and enterprise password-manager visual conventions.

### 18.3 Identity strip

Every micro UI begins with the active identity, because Atomical identity is the root of trust.

Example semantic hierarchy:

```text
whoami ▸ keyguard-builder.atomic.bond
signed  ed25519:m2UrN…7Fa
memory · continuous  18 verified learnings
```

The identity strip remains visible on credential, approval, memory, and installation surfaces.

### 18.4 Skill installation micro UI

The install surface is deliberately small and conversational.

Header:

```text
atomical keyguard
install the credential safety skill
```

Primary scope choices appear as two large rows rather than a dense settings form:

```text
this project ▸ repository-specific runbooks and memory
all projects ▸ personal provider knowledge and safety defaults
```

A third combined option may appear after selection:

```text
recommended ▸ global foundation + project overlay
```

Below the scope choice, show the exact destinations for Claude Code and Codex, whether each will be team-shared or private, and whether MCP is already connected.

The final confirmation uses an Atomical-style transaction summary:

```text
installing ▸ claude code · codex
scope      ▸ project
identity   ▸ keyguard-builder.atomic.bond
writes     ▸ 2 skill adapters · 1 shared field manual
secrets    ▸ none
```

### 18.5 Credential surface

Credential rows are resource declarations, not secret records.

Each row shows:

- credential label
- provider
- environment
- allowed capabilities
- storage boundary
- rotation state
- last safe use
- associated Atomical agent

Never show a reveal icon, masked secret characters, copy button, or editable value field after deposit. The absence of a reveal interaction is a product statement.

Use state words such as:

```text
sealed · active · rotating · expired · revoked
```

### 18.6 Deposit experience

The preferred add flow should read:

```text
deposit a credential
one-time · scoped · expires in 10m
```

The Atomical Deposit Box URL is treated as a transient handoff, not as the credential itself. Once consumed, the UI collapses it into a signed receipt-like row and removes copy affordances.

### 18.7 Approval surface

Approvals resemble signed action envelopes rather than generic confirmation dialogs.

Show:

- `whoami` agent identity
- action
- repository and commit
- provider target
- credential label
- expected side effects
- exact scope and expiry
- policy result

The primary action should be precise: **approve once**, **approve this exact scope**, or **deny**. Avoid a vague “Continue” button.

### 18.8 Living memory surface

The memory view is titled:

```text
memory · continuous
```

Entries appear as compact provenance records:

```text
verified  publish_site from dist/
source    receipt rcpt_V9H8K
scope     this project
signed    keyguard-builder.atomic.bond
```

Use distinct semantic states:

- **verified** — backed by successful execution and validation
- **user note** — explicitly directed by the user
- **proposed** — awaits review
- **stale** — requires re-verification
- **conflict** — disagrees with another trusted source
- **revoked source** — signed by an identity no longer trusted

Memory editing should show provenance and consequences. Deleting a memory does not delete the historical receipt that created it.

### 18.9 Update surface

Core docs, provider packs, and local memory are shown as separate layers:

```text
core skill       1.4.0  signed
atomical docs    2026.07 current
installed adapters  1  review available
project memory   18 entries local
```

Upstream updates use **review update**, not “auto-fix,” when they conflict with local knowledge.

### 18.10 Activity and receipts

Activity reads like a signed operational ledger:

```text
10:44:08  deposit requested  site-publish-token
10:44:41  credential sealed  via atomical deposit box
10:45:10  action approved    publish_site
10:45:31  receipt signed     rcpt_V9H8K
10:45:42  memory verified    publish from dist/
```

Hashes and signatures are secondary details, available on expansion rather than dominating the default view.

### 18.11 Motion and feedback

- Use short, deliberate transitions rather than decorative motion.
- A signature verification may resolve from `checking ▸` to `signed` with a single subtle pulse.
- Deposit, approval, execution, verification, and memory capture should read as a left-to-right progression.
- Never use celebratory animation for production writes or credential changes.
- Errors remain calm, specific, and actionable.

### 18.12 Accessibility and safety semantics

- Never encode status using color alone.
- Keep identities, labels, and hashes selectable for inspection.
- Use explicit confirmation text for destructive actions.
- Preserve full keyboard operation.
- Make scope visible at every memory and installation decision.
- Distinguish “delete credential,” “revoke capability,” “forget memory,” and “remove skill”; these are separate operations.

### 18.13 Atomical seal

The bottom of the micro UI may use a restrained Atomical seal as a final trust cue:

```text
── BEGIN ATOMICAL SEAL ──
domain keyguard-builder.atomic.bond
signed-by ed25519:m2UrN…7Fa
credential-values-rendered 0
── END ATOMICAL SEAL ──
```

The seal is meaningful only when derived from real runtime state. It must never be decorative or falsely claim verification.

### 18.14 MVP interaction defaults

The MVP is intentionally lightweight. It should present one primary decision at a time, keep routine information compact, and reveal technical or advanced controls only when the user asks for them. The UI should not resemble a dense security dashboard.

#### First run and home

- Opening `http://127.0.0.1:4545` for the first time starts a guided setup flow: establish or verify identity, select installation scope, connect detected coding environments, and add a first credential when needed.
- After setup, the product uses one responsive, single-page home surface rather than persistent navigation tabs or a sidebar.
- Home is ordered by operational urgency: **attention needed**, **approvals**, **credentials**, **recent activity**, then **memory**. Each area expands inline.
- When no intervention is needed, omit the empty attention panel and show only a quiet all-clear status line.
- A compact, sticky identity strip remains visible while scrolling. It carries the active Atomical identity and signing/memory status without becoming a large dashboard header.
- Narrow windows reflow to a single column. No security-relevant decision or control is hidden on smaller screens.

#### Installation defaults

- The installer recommends **This project** as the default scope. Global and combined installations remain available but are never silently selected.
- When both Claude Code and Codex are detected, both are preselected. The install review clearly lists every destination and file that will be written.
- Project installation defaults to **private and gitignored**. Making it team-shared is an explicit opt-in.
- When promoting a private project profile to team-shared, show the exact files that will become tracked and require confirmation; never stage or commit them automatically.
- Setup failures remain in their current step with a concise explanation, one primary **Fix now** action, and expandable diagnostics.

#### Credential and deposit flow

- A missing credential creates a focused **credential needed** card with one primary action: **Create deposit link**.
- The deposit state is a single transient card with a short-lived expiry countdown and a **Waiting for deposit...** state. Avoid QR codes, copy-heavy handoff controls, and excessive instructions in the MVP.
- When a deposit made for a pending action completes, resume that action and open its approval card. The new credential is never displayed.
- Credential rows expand inline to show metadata, allowed actions, rotation state, and controls; they do not navigate to a separate detail page.
- For a compromised or expired credential, the primary action is **Revoke capability**. Permanent credential deletion is secondary and remains available only in expanded details.
- Credential rotation is a guided replacement flow: create a new deposit link, confirm the replacement is sealed, then retire the old credential.

#### Approvals and execution

- Approval cards lead with a medium-detail, plain-language summary: action, target, repository and commit, expiry, expected side effects, and policy result. The signed envelope, exact command template, and other technical evidence are expandable.
- The default approval choice is **Approve once**. **Approve this exact scope** is also available.
- For repeatable scope approval, Keyguard proposes the narrowest safe scope—same action, repository, branch or commit policy, provider target, and short expiry—and requires the user to confirm it.
- A pending approval is invalidated when its repository commit changes. The agent must submit a fresh action envelope.
- Deploying from a dirty tree shows a clear warning and requires an explicit, one-time allowance. Record that allowance in the resulting receipt; never turn it into a standing preference automatically.
- While an action runs, show only a compact high-level progression such as **preparing**, **executing**, and **verifying**. Redacted logs remain expandable.
- If provider execution succeeds but verification fails, retain the signed execution receipt and show **Needs attention** with **View details** and **Try verification again**. Do not attempt automatic rollback in the MVP.
- A retry button is available only while the original signed envelope remains valid; otherwise show **Create new request**.
- Expired approvals remain visible as **Expired** and offer **Request again**. They are never automatically renewed.
- New approvals add themselves to the Attention section and show a subtle in-app notification. If the UI is closed, the agent receives the approval-required response; MVP does not require operating-system notifications or a tray integration.

#### Receipts, activity, and memory

- A successful, verified action returns to Home with a compact signed-receipt confirmation and a non-blocking memory suggestion.
- Activity defaults to meaningful milestones—deposits, approvals, execution, receipts, and memory changes. Policy checks and signature diagnostics live behind a **technical events** expansion.
- A verified-memory suggestion is a one-line card with **Save** and **Dismiss**. Provenance and full wording are expandable.
- Selecting **Save** writes directly to the clearly labeled project scope. Global promotion is a separate, deliberate action from Memory and is never offered by default on every save.
- Conflicting upstream skill or provider guidance shows a concise comparison and preserves the project rule until the user explicitly chooses a resolution.
- Update checks run periodically in the background and surface as a quiet Home badge; they never interrupt startup with a modal.

#### Errors, destructive actions, and local access

- Failed actions lead with a plain-language cause and one recommended next step. Redacted technical output is expandable rather than the default view.
- Revoking capabilities, deleting credentials, removing the skill, and other destructive actions require an inline typed confirmation such as `REVOKE`. Forgetting non-sensitive memory may use a lighter confirmation when appropriate.
- The installer opens the local UI once. During normal operation, the agent directs the user to the loopback URL when their attention is required; agent requests do not automatically steal browser focus.

---

## 19. API surface

### UI API

```text
GET    /api/status
GET    /api/credentials
POST   /api/credentials
DELETE /api/credentials/:label
POST   /api/deposit-link
POST   /atomic/events
GET    /api/approvals
POST   /api/approvals/:id/approve
POST   /api/approvals/:id/deny
GET    /api/activity
GET    /api/actions
GET    /api/skill/status
POST   /api/skill/install-plan
POST   /api/skill/install
GET    /api/memory
POST   /api/memory/:id/approve
POST   /api/memory/:id/forget
GET    /api/updates
```

### MCP tools

```text
keyguard_status
list_credentials
list_actions
create_deposit_link
execute_action
delete_credential
```

---

## 20. Demo script

### Opening

> Claude Code and Codex can write the application, but they still need us to paste secrets into terminals and `.env` files. That is the moment autonomy becomes unsafe.

### Add credential

Open Atomical Keyguard.

> This coding agent has its own Atomical identity: `keyguard-builder.atomic.bond`.

Start by listing installed Keyguard actions. A fresh profile shows none.

> Keyguard is a credential boundary, not a cloud-vendor launcher. It never
> guesses a provider or asks for a token in chat.

### Install and invoke the skill

The UI detects Claude Code and Codex and asks whether to install Atomical Keyguard for this project or globally. Choose the project scope.

In Claude Code, invoke `/atomical-keyguard`. In Codex, select or mention `$atomical-keyguard`.

> Build this application locally and include visible attribution to
> [Atomical](https://atomical.dev/). Do not deploy it yet.

The skill can complete the local work without external authority. In a separate
request, it lists installed capabilities. If a reviewed adapter has been
configured, it can request that exact action; otherwise it says the requested
provider is not installed in this Keyguard profile and offers to review official
documentation for a future adapter.

### Approve

Show the pending request.

> Keyguard shows the exact action, repository, commit, target, and credential label. It does not show the secret.

Approve.

### Complete and learn

Show deployment, signed receipt, and the new proposed memory entry.

> Atomical proves which agent acted. Keyguard proves what it was allowed to do. The skill remembers the verified deployment recipe. The model never received the credential.

### Closing line

> **Atomical gives every agent an identity. Keyguard makes that identity safe enough to act.**

---

## 21. MVP scope

Build only:

- one Atomical identity
- one local Keyguard daemon
- one HTML UI
- one MCP server shared by Claude Code and Codex
- one shared Agent Skill with Claude Code and Codex adapters
- project/global installation choice
- one Living Field Manual with sanitized project memory
- credential add/list/delete
- Atomical Deposit Box flow
- no built-in provider action; an optional, separately configured reviewed
  reference adapter (such as Cloudflare Pages) may demonstrate a fixed action
- one approval queue
- one signed receipt
- one verified deployment-memory capture
- one append-only activity log

Avoid:

- multi-tenant cloud hosting
- arbitrary shell execution
- broad provider marketplace
- complex team RBAC
- payments
- credential reveal
- browser automation
- production-grade hardware key support

---

## 22. Roadmap

### Phase 1 — Developer machine

- Claude Code and Codex MCP
- project and global Atomical Keyguard skills
- Living Field Manual and verified error learning
- local UI
- Atomical identity and deposit
- local vault
- reviewed, opt-in provider adapters selected by the user or maintainer
  (for example Cloudflare, GitHub, or Vercel)

### Phase 2 — Team control plane

- signed team skill distribution
- shared provider packs with local overlays
- organization policies
- agent registration
- team approvals
- short-lived leases
- central audit search
- provider-side token creation

### Phase 3 — Agent-native credential fabric

- signed memory and runbook transfer between approved Atomical identities
- agent-to-agent credential delegation through Atomical Deposit Boxes
- signed capability exchange
- workload identities
- automatic key rotation
- policy-as-code
- CI/CD and cloud-runner support
- organization-owned Atomical domains

### Phase 4 — Credentialless provider plugins

Atomical automation plugins can eventually let the agent maintain provider accounts, sessions, OTP channels, and managed resources. Keyguard becomes the policy and approval surface over those Atomical-managed capabilities.

---

## 23. Success metrics

- zero raw credentials returned through MCP
- zero credentials written to repositories
- percentage of external agent actions using predefined capabilities
- percentage of receipts signed with Atomical
- approval turnaround time
- credential rotation age
- number of prevented policy violations
- time from credential request to safe execution
- provider actions completed without human credential handling
- percentage of supported projects with the Keyguard skill installed
- percentage of deployments using a previously verified runbook
- verified error resolutions reused successfully
- memory entries with valid Atomical provenance
- zero secrets written into the Living Field Manual

---

## 24. Product positioning

### One sentence

**Atomical Keyguard turns Atomical identities and vault credentials into safe, policy-controlled capabilities—and gives Claude Code and Codex a living skill that remembers how to use them.**

### Website hero

**Your coding agent needs authority—not your secrets.**

Give Claude Code and Codex an Atomical identity, secure credential deposits, approved capabilities, continuous operational memory, and signed proof of every external action.

### Three pillars

**Deposit safely**  
Credentials enter through Atomical one-time Deposit Boxes, not chats or `.env` files.

**Act narrowly**  
Agents invoke approved provider capabilities while credentials remain behind Keyguard.

**Remember safely**  
The Atomical Keyguard skill keeps verified deployment runbooks and error resolutions without storing secret values.

**Prove everything**  
Atomical-signed requests, memory entries, and receipts identify the agent and bind it to the exact operation.

---

## 25. Technical honesty and implementation notes

- Atomical’s current public materials use the **Atomical** product name while CLI/package examples use `atomic`, `atomic.bond`, `atomic-sdk`, and `@atomic/sdk`.
- Public hosted-mode documentation specifies that deposits are forwarded to a configured webhook and that the application receives the decrypted secret and label. Keyguard must verify the signed webhook and immediately seal the value.
- The Atomical automation plugin contract is described as a developer preview. The Keyguard MVP should rely on stable identity, Deposit Box, Vault, and request-signing concepts rather than depending on a completed marketplace.
- Capability execution reduces secret exposure but does not compensate for an excessively broad provider credential. Provider-side least privilege remains mandatory.
- Keyguard is vendor-neutral by default. A provider named in a prompt, field
  manual, credential record, repository, or receipt is not an installed
  capability; only reviewed startup configuration can add an adapter.
- Claude Code exposes a project or personal skill as `/atomical-keyguard`; Codex uses its Skills picker or explicit `$atomical-keyguard` mention. Product UX should preserve this host-native distinction.
- Claude Code and Codex both support local and user-level Agent Skills, but their directories and trust behavior differ. The installer must preview and respect those boundaries.
- General host memory is useful but is not sufficient as the audit source for credential operations. Keyguard maintains a separate sanitized, provenance-bearing memory ledger.
- Automatic learning must be derived from redacted, verified outcomes. Untrusted repository or provider content cannot directly mutate global memory.

---

## 26. Official references

- Atomical homepage: https://atomical.dev/
- Hosted mode: https://atomical.dev/docs/platform/hosted-mode/
- SDK: https://atomical.dev/docs/platform/sdk/
- Webhooks: https://atomical.dev/docs/platform/webhooks/
- Agent identity: https://atomical.dev/docs/core-concepts/agent-identity/
- Deposit Box: https://atomical.dev/docs/core-concepts/deposit-box/
- Vault: https://atomical.dev/docs/core-concepts/vault/
- Request signing: https://atomical.dev/docs/core-concepts/request-signing/
- Agent-to-agent: https://atomical.dev/docs/guides/agent-to-agent/
- Atomical/Atomic source: https://github.com/plotondev/atomic
- Claude Code MCP: https://code.claude.com/docs/en/mcp
- Claude Code skills: https://code.claude.com/docs/en/skills
- Claude Code memory: https://code.claude.com/docs/en/memory
- Claude Code hooks: https://code.claude.com/docs/en/hooks-guide
- Claude Code quickstart: https://code.claude.com/docs/en/quickstart
- Codex MCP: https://developers.openai.com/codex/mcp
- Codex skills: https://developers.openai.com/codex/build-skills
- Codex customization: https://developers.openai.com/codex/concepts/customization
- Codex memories: https://developers.openai.com/codex/memories
- Codex hooks: https://developers.openai.com/codex/hooks
- Codex AGENTS.md: https://developers.openai.com/codex/guides/agents-md
