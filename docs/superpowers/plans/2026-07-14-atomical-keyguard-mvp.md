# Atomical Keyguard MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable local-first Atomical Keyguard MVP that stores credentials behind a sealed boundary, exposes only narrowly defined capabilities to an MCP client, requires exact human approval for a Cloudflare Pages deployment, and presents the approved lightweight control UI.

**Architecture:** A dependency-free Node.js ESM daemon composes sealed local storage, local Ed25519 identity/signing, deterministic policy and approval services, a fixed Cloudflare adapter, a JSON HTTP API bound to `127.0.0.1`, and a JSON-RPC stdio MCP server. The browser UI is a single responsive document that consumes only secret-free API projections. The installer writes reviewable project/global Agent Skill artifacts and never stages or commits them.

**Tech Stack:** Node.js 25+ built-ins (`node:http`, `node:crypto`, `node:child_process`, `node:test`), browser-native HTML/CSS/JavaScript, no runtime third-party dependencies.

## Global Constraints

- Bind the control plane only to `127.0.0.1`; default port is `4545`.
- State-changing UI requests require same-origin validation and a local session cookie; CORS is never opened with a wildcard.
- No HTTP or MCP route may reveal, copy, export, mask, log, or return a credential value.
- The model may select an allowlisted action and typed parameters, never an executable, shell command, environment variable name, or arbitrary working directory.
- The only MVP provider action is `cloudflare_pages_deploy`; its executable and argument template are fixed.
- The daemon, not an MCP caller, resolves the canonical Git worktree, repository identity, commit, and dirty state. A deployment from a non-Git project fails closed.
- Validate every `relative_path` after normalization and reject paths outside the submitted project root.
- Bind an approval to an exact canonical action envelope, project commit, expiry, nonce, and single-use status; invalidate it when the commit changes.
- Record only labels, hashes, status, and redacted data in activity, receipts, errors, and memory.
- The UI is a guided setup flow followed by one responsive Home surface ordered: attention, approvals, credentials, activity, memory.
- Installation defaults to this-project, detected Claude Code/Codex hosts, and private/gitignored files. It must preview writes and never auto-stage or commit.
- Atomical integration is behind a gateway. A configured `atomic` CLI provides real Deposit Box/Vault behavior; a sealed-local test/demo gateway is explicitly labeled and is never represented as a public hosted Deposit Box.
- An external Deposit Box URL is transient UI-only handoff material. Activity, memory, receipts, and MCP never expose or persist it.
- The repository has no Git metadata at plan time; work in place and do not initialize or alter a repository merely to create commits.

## File Structure

- `package.json` — ESM scripts and Node engine declaration.
- `src/bootstrap.mjs` — compose the application with injectable filesystem, clock, runner, and identity dependencies.
- `src/core/` — canonical JSON, IDs, error mapping, output redaction, and bounded audit helpers.
- `src/storage/` — atomic JSON persistence and AES-256-GCM sealed credential vault.
- `src/identity/` — local Ed25519 key lifecycle, canonical signing, receipt and webhook verification helpers.
- `src/project/` — canonical Git worktree inspector and dirty/commit fingerprinting.
- `src/policy/` — fixed action registry, parameter validators, and deterministic policy decisions.
- `src/services/` — credential/deposit, approval, execution, receipt/activity, and memory lifecycle orchestration.
- `src/providers/cloudflare-pages.mjs` — a single fixed `npx wrangler pages deploy` adapter using `execFile`, never a shell.
- `src/http/server.mjs` — loopback HTTP server and narrow UI API routes.
- `src/mcp/stdio-server.mjs` — stdio JSON-RPC MCP tool dispatcher with the required six tools.
- `src/installer/` — environment discovery, installation plan generation, and safe Agent Skill artifact writes.
- `public/` — static guided setup and single-page Home UI assets.
- `tests/` — Node test files mirroring each boundary and an end-to-end loopback flow.

---

### Task 1: Establish runnable test-first project foundation

**Files:**
- Create: `package.json`, `src/bootstrap.mjs`, `src/core/errors.mjs`, `src/core/canonical.mjs`, `tests/helpers.mjs`, `tests/bootstrap.test.mjs`, `.gitignore`, `README.md`

**Interfaces:**
- Produces `createKeyguardApp(options): Promise<KeyguardApp>` where `KeyguardApp` later exposes `start()`, `stop()`, `services`, and `createHttpServer()`.
- Produces `canonicalJson(value): string` and `sha256(value): string` for every signed/hash-bound record.

- [x] **Step 1: Write the failing bootstrap test** that imports `createKeyguardApp`, creates a temporary data directory, and asserts its `status()` returns a loopback configuration and no secret-bearing fields.
- [x] **Step 2: Run `npm test -- tests/bootstrap.test.mjs`** and verify it fails because the package/application module does not exist.
- [x] **Step 3: Add the minimal ESM package setup, canonical JSON/hash helper, typed Keyguard error helper, and app composition shell**. Keep the constructor injectable for clock, data directory, provider runner, and environment discovery.
- [x] **Step 4: Re-run the focused test and then `npm test`**; both must pass.

### Task 2: Implement sealed credentials, identity, and redaction boundaries

**Files:**
- Create: `src/storage/json-store.mjs`, `src/storage/sealed-vault.mjs`, `src/identity/local-identity.mjs`, `src/core/redaction.mjs`, `tests/sealed-vault.test.mjs`, `tests/redaction.test.mjs`, `tests/identity.test.mjs`
- Modify: `src/bootstrap.mjs`

**Interfaces:**
- `SealedVault.put(metadata, secret): Promise<CredentialProjection>`; `list(): Promise<CredentialProjection[]>`; `readForExecution(label): Promise<string>`; `revoke(label)`; `delete(label)`.
- `CredentialProjection` explicitly excludes ciphertext, IV, auth tag, and value.
- `LocalIdentity.signCanonical(value): SignedValue`; `verifyCanonical(value, signature): boolean`; `signReceipt(receipt): SignedReceipt`.
- `redactSensitiveOutput(text, secret): string` redacts literal, base64, URL-encoded, and JSON-escaped secret variants.

- [x] **Step 1: Write failing vault and redaction tests**: stored data is encrypted, projections contain no value/ciphertext, revoked credentials cannot be read, and all common secret encodings are replaced by `[REDACTED]`.
- [x] **Step 2: Run the focused tests** and confirm failures are about missing implementations.
- [x] **Step 3: Implement atomic JSON writes, a 32-byte `0600` local master-key file outside the project by default, AES-256-GCM sealing, Ed25519 identity persistence with `0600` key files, an Atomical CLI gateway seam, and bounded redaction.**
- [x] **Step 4: Re-run focused tests and full suite.**

### Task 3: Implement allowlisted policy and exact approval envelopes

**Files:**
- Create: `src/project/git-inspector.mjs`, `src/policy/validators.mjs`, `src/policy/action-registry.mjs`, `src/policy/policy-engine.mjs`, `src/services/approvals.mjs`, `tests/git-inspector.test.mjs`, `tests/policy-engine.test.mjs`, `tests/approvals.test.mjs`
- Modify: `src/bootstrap.mjs`

**Interfaces:**
- `validateActionParams(actionName, params, projectRoot): ValidatedParams` supports `relative_path` and `slug` and returns a normalized path constrained to root.
- `GitInspector.inspect(projectRoot): ProjectSnapshot` returns resolved root, repository fingerprint, commit, and dirty-worktree hash; it never trusts an MCP-supplied commit.
- `PolicyEngine.evaluate(request): PolicyDecision` returns either `denied`, `credential_needed`, `approval_required`, or `approved` with a canonical envelope hash.
- `ApprovalService.request(envelope)`, `approveOnce(id)`, `approveScope(id, scope)`, `deny(id)`, and `consume(id, currentCommit)` enforce TTL, hash, commit, and replay rules.

- [x] **Step 1: Write failing Git/policy/approval tests** for non-Git roots, traversal (`../../secret`), symlink escape, unknown actions, missing/revoked credentials, changed commits, expired approvals, consumed approval replay, dirty-tree acknowledgement, and exact reusable scope matching.
- [x] **Step 2: Run focused tests** and verify all failures occur before implementation.
- [x] **Step 3: Implement canonical Git inspection, a registry containing only `cloudflare_pages_deploy`, strict typed validation, deterministic canonical envelope hashes/nonces, short TTL approvals, and narrow repeatable scope proposals. Do not ship an effective wildcard project root.**
- [x] **Step 4: Re-run focused and complete test suites.**

### Task 4: Implement fixed provider execution, signed receipts, activity, and memory

**Files:**
- Create: `src/providers/cloudflare-pages.mjs`, `src/services/execution.mjs`, `src/services/activity.mjs`, `src/services/memory.mjs`, `tests/execution.test.mjs`, `tests/receipt-memory.test.mjs`
- Modify: `src/bootstrap.mjs`

**Interfaces:**
- `CloudflarePagesAdapter.execute({projectRoot, directory, project, secret}): ProviderResult` calls fixed `npx` arguments through `execFile` with token only in child environment.
- `ExecutionService.executeApproved(requestId): Promise<ExecutionResult>` transitions `preparing → executing → verifying`, creates an Atomical-signed receipt, and records redacted activity.
- `MemoryService.createVerifiedCandidate(receipt)`, `save(id)`, `dismiss(id)`, `list()` preserve provenance and project scope.

- [x] **Step 1: Write failing execution tests using an injected fake runner** to prove no shell string is generated, secret output is redacted, the token only reaches the runner environment, receipt records dirty-tree allowance, and verification failure retains a receipt without auto-rollback.
- [x] **Step 2: Run focused tests** and verify the red state.
- [x] **Step 3: Implement the fixed adapter, timeout/error mapping, signed canonical receipt for every provider-attempt outcome, append-only secret-free activity store, memory candidate generation after verified success, and retry validity checks.**
- [x] **Step 4: Re-run focused and complete suites.**

### Task 5: Implement deposits, HTTP API, and signed webhook intake

**Files:**
- Create: `src/services/deposits.mjs`, `src/http/server.mjs`, `src/http/router.mjs`, `tests/http-api.test.mjs`, `tests/webhook.test.mjs`
- Modify: `src/bootstrap.mjs`

**Interfaces:**
- `DepositService.create(metadata): DepositProjection` returns label, short TTL, status, and a UI-only transient URL—not a credential value.
- `DepositService.receiveSigned(event, headers): Promise<CredentialProjection>` verifies a fresh signature before sealing the supplied value and deletes transient handoff state.
- `createHttpServer(app, options)` binds only `127.0.0.1` and provides the spec API plus only required state extensions.

- [x] **Step 1: Write failing HTTP and webhook tests** for loopback-only binding, rejected wildcard CORS/cross-origin mutation, missing/invalid/stale signature rejection, consumed link rejection, credential projection secrecy, UI-only deposit URL handling, approval actions, typed destructive confirmation, and secret-free error payloads.
- [x] **Step 2: Run focused tests** and confirm expected failures.
- [x] **Step 3: Implement a configured Atomical CLI deposit-link adapter plus an explicitly labeled test/demo adapter, signed webhook verification against configured trusted public keys, request-size limits, local session/Origin protections, the required API routes, and uniform safe errors.**
- [x] **Step 4: Re-run focused and full test suites.**

### Task 6: Implement MCP stdio capability boundary

**Files:**
- Create: `src/mcp/stdio-server.mjs`, `tests/mcp.test.mjs`
- Modify: `package.json`, `src/bootstrap.mjs`

**Interfaces:**
- Stdio server handles JSON-RPC `initialize`, `tools/list`, and `tools/call`.
- It exposes exactly `keyguard_status`, `list_credentials`, `list_actions`, `create_deposit_link`, `execute_action`, and `delete_credential`.
- Tool results contain only secret-free structured content. `create_deposit_link` returns a local UI reference, never an external handoff URL; `execute_action` returns `approval_required` rather than executing an unapproved action; `delete_credential` can only create a UI-confirmed destructive request.

- [x] **Step 1: Write failing line-delimited JSON-RPC tests** covering initialization, the exact tool list, schema validation, approval-required execution result, and the absence of `get_secret`/reveal tools.
- [x] **Step 2: Run focused tests** and confirm the server is absent.
- [x] **Step 3: Implement a minimal resilient stdio JSON-RPC loop with request IDs, safe error serialization, and service delegation.**
- [x] **Step 4: Re-run focused and full suites.**

### Task 7: Implement safe installer and portable Agent Skill artifacts

**Files:**
- Create: `src/installer/discovery.mjs`, `src/installer/skill-installer.mjs`, `src/installer/templates.mjs`, `tests/installer.test.mjs`
- Modify: `src/http/server.mjs`, `README.md`

**Interfaces:**
- `discoverEnvironment(projectRoot): DetectionResult` reports hosts, repository, identity, MCP registration, and active policy without writing files.
- `planInstall(selection): InstallPlan` has exact destinations and a default `scope: 'project'`, `sharing: 'private'`.
- `applyInstall(plan): InstallResult` only writes confirmed paths; it never stages or commits files.

- [x] **Step 1: Write failing tests** for project/global destination computation, preselecting detected Claude/Codex, default private `.gitignore` behavior, reviewable file list, global-write opt-in, and no `git add`/commit invocation.
- [x] **Step 2: Run focused tests** and verify failures.
- [x] **Step 3: Implement discovery, plan/apply separation, canonical field manual/skill template, host-native adapter files, concise `AGENTS.md`/`CLAUDE.local.md` guidance shims, and safe private project ignore handling.**
- [x] **Step 4: Re-run focused and full suites.**

### Task 8: Implement the approved lightweight control UI and end-to-end verification

**Files:**
- Create: `public/index.html`, `public/app.js`, `public/styles.css`, `tests/ui-contract.test.mjs`, `tests/e2e.test.mjs`
- Modify: `src/http/server.mjs`, `README.md`

**Interfaces:**
- `/` serves the UI; `/api/status` determines setup versus Home.
- `public/app.js` renders guided setup or compact expandable Home using only API projections.
- All destructive UI actions send an explicit typed confirmation; technical details remain collapsed by default.

- [x] **Step 1: Write failing UI contract and end-to-end tests** for guided-first behavior, sticky real identity data, ordered expandable Home sections, no reveal/copy secret affordance, deposit/approval/execution/memory states, and responsive/accessibility hooks.
- [x] **Step 2: Run focused tests** and confirm the static application is absent.
- [x] **Step 3: Build the single-page UI with setup stepper, inline credential/approval/activity/memory sections, calm Atomical visual language, keyboard-safe disclosures, and compact execution progress.**
- [x] **Step 4: Run `npm test`, start the loopback daemon, exercise setup/status/deposit/approval flows, and visually inspect the Home surface at desktop and narrow width.**

## Final Verification

- [x] Run `npm test` and retain the passing output.
- [x] Search all source, public files, stored fixture outputs, and MCP responses for a secret sentinel; confirm none returns one.
- [x] Confirm `createHttpServer` rejects non-loopback host configuration.
- [x] Confirm provider execution uses `execFile` with a fixed executable/argument template and never invokes a shell.
- [x] Confirm a second use of an approved request fails and a changed commit/expired approval cannot execute.
- [x] Start the daemon and manually inspect the UI’s guided setup and single-page Home at `http://127.0.0.1:4545`.
- [x] Review the whole build for spec coverage, no accidental secret interfaces, and clean test output.
