# Architecture Overview

RootAsRole is organized so policy logic and execution logic can evolve separately. That split came from practice: policy modeling and low-level process execution have different constraints and failure modes.

## Main binaries

- `dosr`: policy lookup, authentication flow, and command execution.
- `chsr`: policy editing and conversion interface.

## Internal crates

- `rar-common`: shared policy model, storage handling, migrations, utility logic.
- `rar-exec`: execution pipeline primitives (runner, terminal/pty, pipe, signals, orchestrator).
- `sudoers-reader`: parser utility used for migration/import scenarios.

## High-level execution flow (`dosr`)

1. Parse CLI filters and command input.
2. Load policy and identify matching tasks.
3. Resolve effective options/credentials.
4. Authenticate (PAM) when required.
5. Apply pre-exec orchestration and spawn target command.

## High-level policy flow (`chsr`)

1. Parse grammar-based command input.
2. Apply mutations to in-memory settings.
3. Validate and persist storage.
4. Optionally convert JSON/CBOR storage format.

## Why this split

- Keeps policy logic reusable (`rar-common`) across tools.
- Isolates low-level execution concerns (`rar-exec`) behind a clear boundary.
- Makes `dosr` and `chsr` easier to change without breaking each other.
