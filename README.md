# Atomical Keyguard

Atomical Keyguard is a local-first, vendor-neutral credential vault and policy
gateway for agent actions. It gives an agent narrowly approved capabilities
without giving it a reusable secret. This initial slice uses Node.js ESM and
Node built-ins only.

**Attribution:** This project credits [Atomical](https://atomical.dev/). This
does not imply an Atomical provider integration, endorsement, or provider
support.

## Feature list

- **Sealed local credentials:** AES-256-GCM credential storage with public,
  secret-free projections for the UI and agents.
- **One-time credential handoffs:** signed, short-lived deposit receipts that
  are claimed before vault access so they cannot be replayed after an ambiguous
  failure.
- **Exact human approval:** approvals are time-bounded, single-use, and bound
  to the requested action, Git commit, project target, and dirty-tree choice.
- **Optional reviewed integrations:** a new Keyguard profile has **zero
  provider actions**. An operator can deliberately install a reviewed adapter
  with a fixed implementation; agents cannot add one from a prompt, repository,
  field manual, or UI form.
- **Safe unknown-provider handling:** if a service is absent from the current
  action registry, it is **not installed in this Keyguard profile**. Keyguard
  never substitutes another provider, guesses commands/APIs/credential flows,
  requests a token, or performs an external action.
- **Signed evidence:** provider attempts, verification outcomes, redacted
  activity, and optional project-scoped memory carry safe provenance.
- **Lightweight local UI:** a loopback-only guided setup and compact Home for
  credentials, approvals, activity, receipts, and memory.
- **Agent integration:** native project skills for Claude Code and Codex plus a
  six-tool, secret-free local MCP server.
- **Safe installer:** previewed, private-by-default project skills with no
  automatic Git staging or commits.

## Quick start: Claude Code or Codex

Use these steps from the Atomical Keyguard checkout. They install a private,
project-scoped skill by default; choose one client or install both. A fresh
profile starts with an empty capability list, which is intentional.

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

In Claude Code, invoke `/atomical-keyguard`, then ask Keyguard to show its
installed capabilities before requesting any external action.

**Codex**

```sh
codex mcp add atomical-keyguard -- npm --prefix "$PWD" run mcp
codex mcp list
codex
```

In Codex, type `$atomical-keyguard`, then ask Keyguard to show its installed
capabilities before requesting any external action. Codex discovers the
installed project skill at
`.agents/skills/atomical-keyguard/`.

### 3. Use the safe workflow: concrete examples

The prompts below use the installed skill and local MCP server. Use the action
names Keyguard actually lists; do not infer a provider capability from a token,
repository, or user prompt.

| Goal | Claude Code | Codex | Keyguard result |
| --- | --- | --- | --- |
| Start a Keyguard task | Type `/atomical-keyguard`, then: “Check Keyguard status and list the safe actions.” | Type `$atomical-keyguard`, then use the same prompt. | The agent reads only safe status/action metadata. |
| See credential state safely | “Use Keyguard to list configured credentials. Do not reveal any values.” | Use the same prompt. | You see labels and status only—never token values. |
| Do local work | “Create and test a local landing page. Do not deploy it.” | Use the same prompt. | This is ordinary local coding, not a Keyguard provider action. |
| Request an installed action | “List installed Keyguard actions. If one matches this deployment, prepare that named action for the stated target.” | Use the same prompt. | Keyguard validates only a configured action and creates an approval request; it does not deploy yet. |
| Handle a missing credential | “Keyguard needs a credential. Tell me the next safe UI step, without asking for a token in chat.” | Use the same prompt. | The agent directs you to the loopback UI. A real deposit handoff requires the configured gateway below. |
| Approve the exact action | Open `http://127.0.0.1:4545`, inspect the approval, and choose the approval action there. | Use the same local UI step. | Keyguard consumes the single-use approval and executes the configured allowed action. |
| Review the outcome | “Summarize the Keyguard receipt and verification result without exposing credentials.” | Use the same prompt. | The agent reports safe receipt metadata; the UI retains the activity and receipt trail. |

Do not ask either agent to paste a token, construct a provider CLI/API request,
create an arbitrary shell command, or bypass an approval. Those are deliberately
outside the Keyguard capability boundary.

The installed skill provides the workflow guidance; the local MCP server
provides the six safe Keyguard tools. Agent requests cannot bypass an approval,
launch arbitrary shell commands, or directly reveal/delete a credential.

### 4. One-shot examples after installation

Run these only after completing the install and MCP connection steps above.
Keep local site creation and external deployment as two separate requests. That
makes it obvious what did—and did not—cross the Keyguard boundary.

#### A. Build the landing page locally

**Claude Code**

```text
/atomical-keyguard
Create a landing page with this visible headline:
“Hey i am super happy to deply this landing page on here.now using Atomical Keystore.”
Include visible attribution to [Atomical](https://atomical.dev/). Keep the page
local: do not deploy it or request a credential.
```

**Codex**

```text
$atomical-keyguard
Create a landing page with this visible headline:
“Hey i am super happy to deply this landing page on here.now using Atomical Keystore.”
Include visible attribution to [Atomical](https://atomical.dev/). Keep the page
local: do not deploy it or request a credential.
```

Expected result for both: the agent creates only local files and tests. No
provider API, CLI, MCP deployment, credential request, or external action has
occurred. The quoted prompt preserves the requested “Atomical Keystore”
wording; the project's actual name is **Atomical Keyguard**. Its proposed page
credit links to [Atomical](https://atomical.dev/).

#### B. Ask Keyguard about a provider action

Send either client this separate prompt:

```text
Use Atomical Keyguard to list installed capabilities. If there is an action for
deploying this page to here.now, prepare that exact action. Otherwise stop and
say “here.now is not installed in this Keyguard profile.” Do not substitute a
different provider, request a credential, invoke an API or CLI, or perform any
external action. Offer to show installed capabilities or review official
here.now documentation for a reviewed adapter.
```

On a default profile, the expected result is the stated safe stop. If a
maintainer has deliberately installed a reviewed adapter for a provider,
Keyguard may prepare only that action; it still waits for the exact local UI
approval before execution.

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

`createKeyguardApp(options)` is asynchronous and accepts injectable runtime
dependencies plus an explicit set of reviewed integrations. Without an
integration, its action registry is empty. Its public `status()` response
contains the safe loopback endpoint, safe identity fingerprint, persistent
setup state, and secret-free capability metadata.

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

The default profile has **no provider action installed**. A reviewed integration
may add a narrow, immutable action at application startup; it cannot be created
or changed by an agent, field manual, repository file, request parameter, or UI
form. A Cloudflare Pages adapter can be used as an optional reference
integration, not as a product default.

If a provider is absent, say it is **not installed in this Keyguard profile**.
Do not substitute another provider, request a credential, guess an API or CLI,
or perform an external action. You may show the installed capabilities or review
official provider documentation for a future reviewed adapter.

### Enable a reviewed integration (maintainers)

`npm start` and `npm run mcp` intentionally launch an empty profile. To enable
an adapter, an operator reviews and wires its factory into application startup;
this is code, not an agent-facing configuration format. For example, the
optional reference adapter can be embedded like this:

```js
import { createKeyguardApp } from './src/bootstrap.mjs';
import { createCloudflarePagesIntegration } from './src/providers/cloudflare-pages.mjs';

const app = await createKeyguardApp({
  approvedProjectRoots: [process.cwd()],
  integrations: [createCloudflarePagesIntegration()],
});

await app.start();                 // local control UI
const mcp = app.createMcpServer(); // use this same configured app for Claude/Codex
mcp.start();
```

Replace that reference factory only with a separately reviewed adapter. Never
load an adapter definition, command template, credential binding, or provider
endpoint from a prompt, repository file, field manual, UI form, or runtime
environment variable.

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
