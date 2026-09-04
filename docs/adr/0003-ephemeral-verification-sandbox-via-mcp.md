# Payloads execute in worker-owned ephemeral containers, not in hermes's sandbox

hermes's `terminal.backend = docker` is one long-lived shared container, which would cross-contaminate verifications and merge egress logs across checks. Instead, the Hermes Agent only *decides* what to verify and *interprets* results; actual PoC execution goes through an MCP tool (`run_in_sandbox`) exposed by the worker, which starts a fresh `docker run --rm` container per verification from the tooling image, captures stdout and full network egress, and returns JSON evidence before the container destroys itself.

## Considered options

- **Use hermes's shared container** — zero extra code, but state leaks between verifications and per-check network evidence (what the report claims the PoC did) becomes impossible to prove.

## Consequences

~1 day of build cost (FastMCP server + Docker SDK) and a few seconds' startup latency per verification. In exchange: clean evidence per check, the agent never holds a persistent shell, and egress auditing is centralized in the worker next to the Scope Validator.
