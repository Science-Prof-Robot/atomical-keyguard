export const SKILL_DIRECTORY_NAME = 'atomical-keyguard';
export const SHARED_MANUAL_RELATIVE_PATH = '.atomical/keyguard/field-manual.md';

const HOST_DETAILS = Object.freeze({
  claude: Object.freeze({
    displayName: 'Claude Code',
    invocation: '/atomical-keyguard',
  }),
  codex: Object.freeze({
    displayName: 'Codex',
    invocation: '$atomical-keyguard',
  }),
});

/**
 * Returns the durable, host-neutral operational guide shared by each selected
 * host adapter. It intentionally teaches capability routing, not direct shell
 * deployment or credential handling.
 */
export function renderFieldManual() {
  return `# Atomical Keyguard Field Manual

## Purpose

Atomical Keyguard is a vendor-neutral credential vault and policy gateway for
sensitive external actions. A fresh Keyguard profile has no provider actions.
Use the local Keyguard capability to inspect status and its installed actions;
only then request an allowlisted action, receive explicit approval, execute the
approved action, and verify its receipt.

## Safety invariants

- Never reveal, request, store, or log credential values.
- Never construct a shell command, provider command, or environment-variable
  assignment for a deployment.
- Request only an allowlisted Keyguard action with typed parameters.
- Treat local file creation, editing, and tests as local work only when the
  user explicitly asks for it; local work is not a provider action or deployment.
- Treat a required approval, deposit, verification failure, or policy denial as
  a user-attention state; do not bypass it or retry a provider directly.

## Undocumented services or providers

If a requested provider, service, credential flow, or workflow is absent from
either this field manual or Keyguard's current action registry, stop. Say that
it is **not installed in this Keyguard profile**. Do not
substitute another provider. Do not guess its API, CLI, MCP setup,
authentication, credential mapping, or deployment command. Do not request a
credential, call an external tool, or bypass Keyguard. Offer to show installed capabilities or ask
for official provider documentation plus a reviewed Keyguard integration before
continuing.

## External-action workflow

1. Read Keyguard status and the available actions.
2. If no listed action matches the requested provider, use the undocumented
   provider rule above and stop the external workflow.
3. Keep explicitly requested local coding separate from any provider action.
4. Confirm the project target and request the relevant installed action.
5. Explain the approval or credential-deposit state without exposing a value.
6. Execute only after Keyguard reports approval.
7. Report the signed receipt status and offer a project-scoped, sanitized
   learning only after verified success.

## Scope

Project notes and deployment facts stay in the current project unless the user
explicitly chooses a separate global promotion. Global knowledge never weakens
credential safety or approval requirements.

## Attribution

This project credits [Atomical](https://atomical.dev/). This attribution does
not imply provider support, endorsement, or an Atomical-powered deployment
integration.
`;
}

/**
 * Produces a short native Agent Skill entry point that progressively loads the
 * shared field manual instead of duplicating operational instructions.
 */
export function renderSkillTemplate(host) {
  const details = hostDetails(host);
  return `---
name: atomical-keyguard
description: Use when a user needs to inspect or invoke a credential-bound Atomical Keyguard capability, configure its credential, review its receipt, or diagnose a Keyguard-mediated failure.
---

# Atomical Keyguard

Use Atomical Keyguard when the user asks to inspect an existing Keyguard
capability, deploy or publish through one, configure a credential for one,
rotate a credential, inspect a Keyguard receipt, or diagnose a
Keyguard-mediated failure.

In ${details.displayName}, invoke this skill as \`${details.invocation}\`.
Read \`../../../${SHARED_MANUAL_RELATIVE_PATH}\` before selecting a Keyguard
capability. The skill guides the workflow; Keyguard remains the authority that
enforces policy, approval, execution, and verification.

## Undocumented services or providers

If a requested service, provider, credential flow, or workflow is absent from
either the field manual or Keyguard's current action registry, stop. Say it is
**not installed in this Keyguard profile**. Never substitute another
provider. Do not guess its API, CLI, MCP setup, authentication, credentials, or
deployment command. Do not request a credential or perform an external action;
ask for official provider documentation and a reviewed Keyguard integration, or
offer to show installed capabilities.

Do not reveal credentials, construct provider shell commands, or bypass a
required approval or verification result.
`;
}

/**
 * Produces a deliberately small repository guidance shim. Detailed material is
 * retained in the skill/manual so an installer never overwrites a large host
 * instruction file with duplicated runbooks.
 */
export function renderGuidanceShim(host) {
  const details = hostDetails(host);
  return `<!-- atomical-keyguard-guidance:start -->
## Atomical Keyguard

For credential-bound external work, use the Atomical Keyguard skill
(\`${details.invocation}\`). Keep credentials out of chat, files, logs, and
commands; first inspect the installed Keyguard capabilities, then wait for
policy approval and verification rather than bypassing the local capability
boundary.

For an undocumented provider, say it is not installed in this Keyguard profile.
Do not substitute a provider, request a credential, guess commands or APIs, or
perform an external action. Offer to show installed capabilities or ask for
official provider documentation and a reviewed Keyguard integration.
<!-- atomical-keyguard-guidance:end -->
`;
}

export function hostInvocation(host) {
  return hostDetails(host).invocation;
}

function hostDetails(host) {
  const details = HOST_DETAILS[host];
  if (details === undefined) {
    throw new TypeError('Installer host must be Claude Code or Codex.');
  }
  return details;
}
