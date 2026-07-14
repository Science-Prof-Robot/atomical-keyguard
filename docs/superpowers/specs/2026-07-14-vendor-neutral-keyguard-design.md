# Vendor-Neutral Keyguard Design

## Goal

Make Atomical Keyguard a vendor-neutral credential vault and policy gateway.
The default installation must have no enabled external provider. Cloudflare
Pages remains a reviewed reference integration that a developer explicitly
installs at application startup; it is not product default behavior.

## Product boundary

Keyguard is more than a password store: it seals credentials, records agent
identity, binds an approval to a narrow capability, and produces a signed
receipt. It does not let an agent read a secret or invent a provider command.

```text
Sealed vault + identity + approvals + receipts     (default core)
                         +
explicit reviewed integrations                     (optional capabilities)
```

An integration is trusted application code. It may be supplied only when
`createKeyguardApp()` starts. An MCP request, repository instruction, prompt,
or provider document can never install an integration, supply an executable,
set an environment-variable mapping, or expand an existing action.

## Runtime model

`createActionRegistry({ approvedProjectRoots, integrations })` creates an
immutable registry. With no integrations it has no actions and no credential
handoff bindings. Each integration contributes one or more actions with:

- an immutable action name and version;
- a credential binding (`label` and `provider`);
- public, bounded parameter schema metadata;
- a trusted `prepare` function that turns a request into canonical signed
  params and target data;
- a trusted `execute` function; Keyguard core invokes its configured safe
  verification hook from the resulting signed receipt.

The policy engine signs the prepared action name, version, complete credential
binding (label and provider), params, target, repository snapshot, expiry, and
nonce. Approval and execution compare that binding against the currently
installed action. The sealed vault releases a secret only for the same binding.
Execution re-runs the adapter's trusted `prepare` function and compares its
canonical params/target immediately before secret access and again before
launch. Receipt, activity, and memory validation use generic action identifiers
and canonical data, never a Cloudflare-specific constant.

The registry starts empty. `list_actions` returns `[]`; no runner is created
or invoked. A configured Cloudflare integration preserves its fixed `execFile`
and Wrangler argv behavior, but is loaded only explicitly.

## Credential handoffs

The sealed vault already accepts generic metadata. A separate registry-derived
credential catalog controls which labels can receive a Deposit Box handoff.
No adapter means no credential handoff card. The handoff record, rather than
an incoming webhook, remains authoritative for the label and metadata.

## Agent and UI UX

The skill always reads the locally installed capability list first. If a user
names a provider that is not installed, it says the provider is not installed
in this Keyguard profile, makes no credential/API/CLI call, and never suggests
a substitute vendor. It separates ordinary local site work from an external
deployment request; it may write local files only when the user explicitly
asked it to do so.

The local UI stays lightweight: it lists credentials and installed actions. If
there are no action bindings, it says “No integrations enabled” instead of
showing a default Cloudflare credential handoff.

## Compatibility and migration

Existing sealed credential records remain valid because their metadata is
already generic. Historical signed approvals, receipts, activity, and memory
are accepted only through structural generic validation; old pending actions
cannot execute unless the exact integration/action version remains installed.
Unknown or removed actions fail closed. Signed historical records are never
rewritten.

## Non-goals

- Arbitrary shell-command, API, or environment-variable templates from agents,
  repository files, or JSON configuration.
- Automatic installation of a provider from its documentation.
- A provider marketplace or user-supplied module paths.
- A live `here.now` integration without its reviewed adapter.
