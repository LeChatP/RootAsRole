# Security Model

RootAsRole enforces delegated privilege. In practice, policy quality is the main security boundary.

## Security controls

- PAM-based authentication for `dosr`
- Capability-oriented privilege model
- Optional timestamp/timeout behavior
- Immutable policy file workflow
- Hardened policy editor path in `chsr editor` (landlock/seccomp)

## Operational safeguards

- Grant only required capabilities.
- Prefer explicit command allow-lists.
- Use dedicated roles for automation.
- Force explicit role/task selection in scripts.
- Review and test policy changes before deployment.

## Typical risks

- Over-broad command patterns
- Unnecessary capability grants
- Ambiguous task overlap
- Reusing interactive roles for unattended jobs

## Minimal hardening checklist

1. Keep `/etc/security/rootasrole.json` protected and immutable in production.
2. Restrict `chsr` usage to a small admin set : 
  - Implement review processes for policy changes.
  - Implement segregation of duties for policy management and execution.
3. Use `dosr -i` during policy validation (requires to allow `dosr -i` in policy for testing).
4. Add CI checks for policy syntax and expected command paths.
5. Track policy changes in version control.
