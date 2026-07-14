# Vendor-Neutral Keyguard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the default Atomical Keyguard runtime a vendor-neutral sealed
credential vault with zero enabled provider actions, while retaining Cloudflare
Pages as an explicit, reviewed reference integration.

**Architecture:** Replace the singleton Cloudflare action with an immutable
registry of startup-installed trusted integrations. The registry prepares,
revalidates, executes, and verifies signed generic capability requests. The
vault, approvals, receipts, handoffs, MCP surface, UI, and installed skills use
the registry instead of hard-coded provider identifiers. No agent-controlled
configuration can supply a command, environment variable, or integration.

**Tech Stack:** Node.js 25+ ESM and built-ins, `node:test`, no runtime
third-party dependencies.

## Global Constraints

- `createKeyguardApp()` with no integrations must list no actions and never
  launch a provider process.
- Integrations are reviewed code passed at daemon startup only; HTTP, MCP,
  prompts, repository files, and provider docs cannot add or modify one.
- Every action binds its immutable name, version, full credential binding,
  canonical prepared params, target, Git snapshot, approval, and receipt.
- Preserve the no-secret boundary: no value may reach UI, MCP, logs, activity,
  memory, receipt, or agent context.
- Preserve loopback-only HTTP, exact approval, one-time handoff, and fixed
  Cloudflare `execFile` safety behavior when the optional integration is used.
- An unknown provider must stop before credential/API/CLI activity and must
  never propose Cloudflare as a substitute.

---

### Task 1: Add a default-empty trusted integration registry

**Files:**
- Modify: `src/policy/action-registry.mjs`, `src/policy/policy-engine.mjs`,
  `src/policy/validators.mjs`, `src/providers/cloudflare-pages.mjs`,
  `src/bootstrap.mjs`
- Modify tests: `tests/policy-engine.test.mjs`, `tests/bootstrap.test.mjs`,
  `tests/execution.test.mjs`

**Interfaces:**

```js
createActionRegistry({ approvedProjectRoots, integrations = [] })
registry.list()                 // public action descriptors
registry.get(actionName)        // private immutable action descriptor
registry.prepare(actionName, params, snapshot)
registry.execute(envelopeBody, secret)
registry.getCredentialBinding({ label, provider })
createCloudflarePagesIntegration(options)
```

- [ ] **Step 1: Write failing tests** that prove a default registry lists `[]`,
  denies an unknown action before Git/vault/runner work, and accepts a test-only
  non-Cloudflare integration supplied at startup.
- [ ] **Step 2: Run** `node --test tests/policy-engine.test.mjs tests/bootstrap.test.mjs`
  and confirm the failures identify the current fixed Cloudflare registry.
- [ ] **Step 3: Implement the immutable integration contract.** Require a
  unique action name, bounded version, exact credential binding, public schema,
  and trusted `prepare`/`execute` methods. Move the Pages parameter validation
  behind `createCloudflarePagesIntegration()`. Do not expose command mappings
  in the registry’s public projection.
- [ ] **Step 4: Change bootstrap** to use `options.integrations ?? []`; do not
  construct a Cloudflare adapter by default.
- [ ] **Step 5: Re-run focused tests** and keep the existing Cloudflare adapter
  tests by injecting the explicit integration.

### Task 2: Generalize signed policy, approvals, execution, and audit records

**Files:**
- Modify: `src/services/approvals.mjs`, `src/services/execution.mjs`,
  `src/services/activity.mjs`, `src/services/memory.mjs`, `src/bootstrap.mjs`
- Modify tests: `tests/approvals.test.mjs`, `tests/execution.test.mjs`,
  `tests/receipt-memory.test.mjs`, `tests/identity.test.mjs`

**Interfaces:**

```js
EnvelopeBody = {
  action, actionVersion, agent, credentialLabel, credentialProvider, params, target,
  project, requestedAt, expiresAt, nonce, policyVersion
}
```

- [ ] **Step 1: Write failing tests** with a fake integration whose action and
  credential are not Cloudflare. Assert its prepared target is signed, an
  approval becomes unusable after its action version changes/removes, and a
  successful receipt/memory contains generic Keyguard action text.
- [ ] **Step 2: Run** the focused approval, execution, and receipt-memory tests
  and confirm they fail on fixed action/credential validation.
- [ ] **Step 3: Implement generic structural validation.** Validate signed
  canonical plain-JSON params/targets; use registry action/version checks at
  request and execution time; compare generic target fingerprints for reusable
  scopes. Keep historical signed records readable structurally and fail closed
  when their action is no longer installed.
- [ ] **Step 4: Route execution through `registry.execute()`** after approval
  consumption and revalidation. Preserve redaction and clear the secret before
  any result is returned.
- [ ] **Step 5: Make activity and memory action-neutral** and retain existing
  signatures/receipt provenance checks.
- [ ] **Step 6: Re-run focused tests and `npm test`.**

### Task 3: Make handoffs, MCP, HTTP, and UI registry-driven

**Files:**
- Modify: `src/services/deposits.mjs`, `src/mcp/stdio-server.mjs`,
  `src/http/router.mjs`, `public/app.js`, `src/bootstrap.mjs`
- Modify tests: `tests/webhook.test.mjs`, `tests/mcp.test.mjs`,
  `tests/http-api.test.mjs`, `tests/e2e.test.mjs`, `tests/ui-contract.test.mjs`

**Interfaces:**

```js
depositService.create({ label, provider }) // succeeds only for installed binding
list_actions()                              // returns public installed actions
execute_action({ action, agentId, params, projectRoot })
```

- [ ] **Step 1: Write failing tests** that a default app exposes an empty action
  list, has no deposit handoff available, and cannot launch a runner; a fake
  installed integration accepts only its own credential binding.
- [ ] **Step 2: Run** focused webhook, MCP, HTTP, and UI tests to observe fixed
  Cloudflare schemas and UI state fail.
- [ ] **Step 3: Derive deposit allowlisting from registry credential bindings.**
  Preserve the one-time handoff and ensure received webhook metadata cannot
  override the handoff’s binding.
- [ ] **Step 4: Replace static MCP constants/schemas with bounded generic
  action inputs validated against the runtime registry.** Keep exactly the six
  secret-free tool names and do not allow direct execution or deletion.
- [ ] **Step 5: Project generic public action descriptors in HTTP and update
  the UI to render “No integrations enabled” with no default provider card.
- [ ] **Step 6: Re-run focused tests and `npm test`.**

### Task 4: Make installed skills and product documentation adapter-neutral

**Files:**
- Modify: `src/installer/templates.mjs`, `README.md`,
  `Atomical_Keyguard_Master_Product_Spec_v1.1.md`
- Modify tests: `tests/installer.test.mjs`

- [ ] **Step 1: Write failing installer-template assertions** for “credential-
  bound external action,” installed-capability discovery, no vendor
  substitution, and safe stop before external activity.
- [ ] **Step 2: Update the field manual and host shims** to separate ordinary
  coding from protected external actions and say an absent provider is “not
  installed in this Keyguard profile.”
- [ ] **Step 3: Rewrite README quick start and examples** around a default
  empty registry and optional reference adapters. Keep the [Atomical](https://atomical.dev/)
  attribution while removing Cloudflare from primary product copy.
- [ ] **Step 4: Add a concise spec amendment** that labels Cloudflare as an
  optional reference integration and elevates provider packs as the core
  extension model.
- [ ] **Step 5: Run** `node --test tests/installer.test.mjs` and `npm test`.

### Task 5: Verify migration safety and publish

**Files:**
- Modify as needed only for test-proven compatibility handling.
- Test: full `tests/` suite plus a newly added generic integration end-to-end
  test.

- [ ] **Step 1: Add tests** that an old signed receipt/memory record remains
  read-only/valid structurally, while a removed action cannot consume a pending
  approval or handoff.
- [ ] **Step 2: Run `npm test`** and inspect the complete output for zero
  failures.
- [ ] **Step 3: Run `git diff --check`**, review the diff for no secret values
  or command-template escape hatches, then commit and push the public branch.
