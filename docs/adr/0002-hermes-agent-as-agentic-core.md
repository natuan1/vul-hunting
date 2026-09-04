# hermes-agent as the agentic core, integrated via its API server

The AI layer (detection + verification reasoning) runs on NousResearch's hermes-agent as a separate gateway service, and the Python worker talks to it over its OpenAI-compatible API server (`:8642`, Runs API + SSE) — not by embedding it as a library and not through a hand-rolled LangChain/Claude-direct stack. We get its tool ecosystem (terminal, memory, MCP toolsets, approvals/allowlists, skill authoring per the agentskills.io `SKILL.md` standard) for free, and swap the LLM provider (OpenRouter by default) without touching our code.

## Considered options

- **Claude/OpenAI API direct + custom orchestration** — full control, but we re-implement sessions, tool dispatch, approvals, and skill management hermes already ships.
- **Python library embedding (`run_agent.AIAgent`)** — exists but undocumented (constructor and result-reading APIs require reading source); too fragile to build on.

## Consequences

Per-request toolset selection is not possible through the API server (only model/provider) — accepted, since every task is a security task and the full toolset is appropriate. Headless runs default to denying approval-gated commands, so tool commands must be pre-allowlisted in hermes config.
