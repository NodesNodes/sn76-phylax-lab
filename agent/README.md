# Agent profiles

The active LLM-enabled set contains four submissions across three tracks:
packages (`sn76`), skills (`sn76_2`), repositories-independent (`sn76_3`) and
repositories-wave6 (`sn76_4`). MCP remains on the legacy universal dispatcher
and is outside this rollout.

Every active non-MCP deployment is a single Python file. During the build,
`phylax_llm_layer.py` is inlined into packages and both repository sources;
skills carries the equivalent layer directly. The model is called only through
the validator-provided metered inference proxy.

All four specializations use one submitted source file:
`phylax_agent.py`, entrypoint `agent_main`.

The validator supplies `context.track`; the entrypoint dispatches to a
track-specific analyzer. Keeping a single source avoids four copies drifting
apart while still producing four independently registered agents, one per
wallet hotkey.

| Track | Env | Label | State |
|---|---|---|---|
| packages | `.env` | `phylax-packages-v1` | active |
| mcp_servers | `.env.mcp` | `phylax-mcp-v1` | active |
| skills | `.env.skills` | `phylax-skills-v1` | prepared |
| repositories | `.env.repositories` | `phylax-repositories-v1` | prepared |

The two prepared env files intentionally have blank `WALLET_HOTKEY` and
`PHYLAX_EXECUTION_API_KEY` values. Do not submit them until a distinct hotkey
has been created and registered on SN76.

Tracked safe templates live under `configs/`. Local `.env*` files are ignored.
