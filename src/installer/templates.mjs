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

Atomical Keyguard is the approval boundary for sensitive deployment work. Use
the local Keyguard capability to inspect status, request an allowlisted action,
receive explicit approval, execute the approved action, and verify its receipt.

## Safety invariants

- Never reveal, request, store, or log credential values.
- Never construct a shell command, provider command, or environment-variable
  assignment for a deployment.
- Request only an allowlisted Keyguard action with typed parameters.
- Treat a required approval, deposit, verification failure, or policy denial as
  a user-attention state; do not bypass it or retry a provider directly.

## Undocumented services or providers

If a requested provider, service, credential flow, or workflow is not explicitly
documented in this field manual and present in Keyguard's current action registry,
stop. Do not guess its API, CLI, MCP setup, authentication, credential mapping,
or deployment command. Do not call an external tool or bypass Keyguard. Explain
that it is not currently supported and ask for official provider documentation
plus a reviewed Keyguard integration before continuing.

## Deployment workflow

1. Read Keyguard status and the available actions.
2. Confirm the project target and request the relevant action.
3. Explain the approval or credential-deposit state without exposing a value.
4. Execute only after Keyguard reports approval.
5. Report the signed receipt status and offer a project-scoped, sanitized
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
description: Guide safe, approval-bound Atomical Keyguard deployment workflows.
---

# Atomical Keyguard

Use Atomical Keyguard when the user asks to deploy, publish, configure a
provider credential, rotate a credential, inspect a Keyguard receipt, or
diagnose a Keyguard-mediated failure.

In ${details.displayName}, invoke this skill as \`${details.invocation}\`.
Read \`../../../${SHARED_MANUAL_RELATIVE_PATH}\` before selecting a Keyguard
capability. The skill guides the workflow; Keyguard remains the authority that
enforces policy, approval, execution, and verification.

## Undocumented services or providers

If a requested service, provider, credential flow, or workflow is not documented
in the field manual and present in Keyguard's current action registry, stop.
Never guess its API, CLI, MCP setup, authentication, credentials, or deployment
command; ask for official provider documentation and a reviewed Keyguard
integration.

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

For credential-bound deployment work, use the Atomical Keyguard skill
(\`${details.invocation}\`). Keep credentials out of chat, files, logs, and
commands; wait for Keyguard policy approval and verification rather than
bypassing the local capability boundary.

For an undocumented provider, stop and ask for official provider documentation
and a reviewed Keyguard integration rather than guessing commands or credentials.
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
