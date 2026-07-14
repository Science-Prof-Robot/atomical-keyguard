# Atomical Keyguard

Atomical Keyguard is a local-first security daemon foundation for policy-bound
agent operations. This initial slice uses Node.js ESM and Node built-ins only.

## Quick start: Claude Code or Codex

Use these steps from the Atomical Keyguard checkout. They install a private,
project-scoped skill by default; choose one client or install both.

### 1. Start Keyguard

Node.js 25+ is required. In one terminal, keep the local daemon running:

```sh
npm test
npm start
```

Open `http://127.0.0.1:4545`. In guided setup, keep **this project** selected,
leave the detected host checked, choose **Prepare install plan**, review the
relative destinations, then choose **Install selected skill**. No credentials
are shown or copied during setup.

### 2. Connect your coding client

The installer writes the native skill files. Restart or open a new client
session from this repository after setup, then register the local MCP server so
the skill can use Keyguard's safe tools.

**Claude Code**

```sh
claude mcp add --transport stdio --scope local atomical-keyguard -- npm --prefix "$PWD" run mcp
claude mcp list
claude
```

In Claude Code, invoke `/atomical-keyguard`, or ask for a deployment or
credential-bound workflow and let the installed skill activate when relevant.

**Codex**

```sh
codex mcp add atomical-keyguard -- npm --prefix "$PWD" run mcp
codex mcp list
codex
```

In Codex, type `$atomical-keyguard`, or ask for a Keyguard-mediated deployment
workflow. Codex discovers the installed project skill at
`.agents/skills/atomical-keyguard/`.

### 3. Use the safe workflow

1. Ask the agent to inspect Keyguard status or prepare the allowlisted action.
   For example: “Use Atomical Keyguard to prepare a Cloudflare Pages deploy of
   `./dist` for project `my-site`.”
2. When Keyguard requests attention, return to `http://127.0.0.1:4545` to add
   a credential or approve the exact action. Do not paste credentials into the
   agent chat, terminal, prompts, or project files.
3. Keyguard performs the approved action and shows a compact signed receipt in
   the local UI. Review the receipt or activity there; the agent never receives
   the credential value.

The installed skill provides the workflow guidance; the local MCP server
provides the six safe Keyguard tools. Agent requests cannot bypass an approval,
launch arbitrary shell commands, or directly reveal/delete a credential.

> **Live credential handoffs need configuration.** The default build has no
> public deposit gateway. Configure a compatible Atomical gateway and trusted
> webhook verifier before using the credential-deposit step in a real project.

For current client reference, see [Claude Code skills](https://code.claude.com/docs/en/slash-commands),
[Claude Code MCP](https://code.claude.com/docs/en/mcp), [Codex skills](https://learn.chatgpt.com/docs/build-skills.md),
and [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp.md).

## Run the tests

```sh
npm test
```

## Run the local daemon

```sh
npm start
```

The daemon accepts no host or port flags. It starts the fixed loopback control
server at `http://127.0.0.1:4545`, reports only that local URL to stderr, and
stops cleanly on `SIGINT` or `SIGTERM`. It never sends application status,
credential material, filesystem paths, or provider output to the terminal.

The loopback UI trusts the local OS account and process environment that can
reach it. It is not OS-user authentication, so do not treat a local session as
an identity boundary between local users or untrusted local processes.

## Foundation contract

`createKeyguardApp(options)` is asynchronous and accepts injectable `clock`,
`dataDirectory`, `providerRunner`, and `environmentDiscovery` dependencies.
Its public `status()` response contains the safe loopback endpoint, safe
identity fingerprint, and persistent setup state.

`canonicalJson(value)` produces a stable, key-sorted JSON representation for
plain JSON records. `sha256(value)` hashes that canonical representation with
SHA-256, so later approvals and receipts can bind their exact record content.

Credentials are stored only behind the sealed vault boundary. Public status,
HTTP, MCP, activity, receipt, and memory projections never return or expose a
credential value.

## Local control UI

The loopback server serves a dependency-free control surface at `/`, with its
fixed assets at `/app.js` and `/styles.css`. Start it from your local runtime:

```js
import { createKeyguardApp } from './src/bootstrap.mjs';

const app = await createKeyguardApp();
await app.start();
// Open http://127.0.0.1:4545
```

The first browser visit presents guided setup, then a responsive Home ordered
by attention, approvals, credentials, activity, and memory. The sticky
runtime strip is derived from `/api/status`; it does not invent an external
identity that the API has not projected.

UI mutations use the same local session, same-origin, and CSRF protections as
the JSON API. A deposit handoff URL exists only in the current page's memory:
it is cleared after completion, expiry, or reload. Credential values are never
rendered by the UI, destructive removal requires typing `DELETE`, and local
credential revocation requires the exact `REVOKE` confirmation. Revocation
returns the same secret-free credential metadata projection as listing.

Atomical deposit-link creation is fail-closed: it remains unavailable until a
compatible gateway is explicitly configured. The default gateway is not a live
deposit service.

## Current execution allowlist

Only the fixed Cloudflare Pages deploy action is currently allowlisted. Other
providers and arbitrary commands are not enabled or request-configurable.

## Install the portable Agent Skill

The installer is deliberately a two-step, filesystem-only workflow. Discovery
and planning do not write files; inspect the returned plan before explicitly
applying it.

```js
import { discoverEnvironment } from './src/installer/discovery.mjs';
import { applyInstall, planInstall } from './src/installer/skill-installer.mjs';

const discovery = await discoverEnvironment('/absolute/path/to/project');
const plan = await planInstall({ discovery });

// Review plan.hosts and every item in plan.files first.
await applyInstall(plan, { confirmed: true });
```

Confirmation is intentionally not stored in an `InstallPlan`: every apply call
must supply its own explicit `{ confirmed: true }` value. A global or combined
plan also needs a separate apply-time `{ globalOptIn: true }` value.

The default is **this project**, **private**, and every detected Claude Code or
Codex host is preselected. A private project install writes a shared field
manual under `.atomical/keyguard/`, host-native `SKILL.md` adapters under
`.claude/skills/atomical-keyguard/` and/or `.agents/skills/atomical-keyguard/`,
small `CLAUDE.local.md`/`AGENTS.md` guidance shims, and only the necessary
entries in `.gitignore`.

Global or combined scope remains available, but must be selected in the plan
and requires a second explicit opt-in when applying:

```js
const plan = await planInstall({
  homeDirectory: '/absolute/path/to/home',
  hosts: ['claude', 'codex'],
  projectRoot: '/absolute/path/to/project',
  scope: 'global',
});
await applyInstall(plan, { confirmed: true, globalOptIn: true });
```

The installer never invokes a shell, stages files, or creates Git commits. It
rejects tampered plans, symlinked targets, group/world-writable selected roots
and parents, and existing generated files whose contents differ from the
reviewed artifact. Existing regular files are opened with no-follow,
nonblocking descriptors and bounded reads; newly created artifacts receive a
post-write canonical-containment check and a best-effort cleanup on failure.

On macOS and other pure-Node runtimes without descriptor-relative `openat`, a
concurrently malicious process running as the same user can still race a
pathname after these checks. The installer therefore writes only non-secret
templates and must run on a trusted local filesystem; it cannot provide an
atomic defense against that same-UID parent-directory race.
