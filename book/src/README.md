# Introduction

RootAsRole comes from my PhD work on least administrative privilege.

The initial motivation was simple: in many production environments, administrators still receive broad and persistent root access, even when they only need a narrow set of actions.

That creates two problems at the same time:

- intentional abuse by insiders with too much privilege,
- unintentional compromise through supply-chain or tooling issues.

So the practical question became: how do we delegate admin work without delegating full root?

## Project objectives

- Apply PoLAP in day-to-day operations.
- Delegate tasks, not unrestricted identities.
- Use capabilities when enough; avoid full root when not needed.
- Keep policy explicit and auditable.

## Core components

- `dosr`: runs a command only if a role/task match is found.
- `chsr`: creates and maintains policy, roles, tasks, and execution options.
- `capable`: helps observe capability requirements during validation and tests.

## Why another tool?

Linux already has strong primitives (permissions, ACLs, capabilities, MAC), but composing them coherently for co-administration is difficult. In practice, complexity often leads to over-permissioned shortcuts.

RootAsRole is my attempt to make that tractable: a policy-driven orchestrator that keeps delegation fine-grained and execution just-in-time.

Start with [Installation](guide/installation.md), then follow [First Policy in 10 Minutes](getting-started/quickstart.md).

For internals, see [Architecture Overview](architecture/overview.md).