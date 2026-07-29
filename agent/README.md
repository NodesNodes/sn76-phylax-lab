# Agent profiles

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
