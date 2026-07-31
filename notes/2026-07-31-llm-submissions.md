# 2026-07-31 — LLM-enabled submission receipts

All four active non-MCP agents passed the Python 3.11 validator-image preflight
and were accepted by `https://api.phyi.dev`.

| Wallet | Track | Public name | Version | SHA-256 | Model |
|---|---|---|---:|---|---|
| `sn76` | packages | `phylax-packages-standalone-v2` | 4 | `99906d06927b18449fee968fcee3a7241b583e47af4919ffb62e768344603198` | `openai/gpt-4.1-mini` |
| `sn76_2` | skills | `phylax-skills-v1` | 3 | `c9cba1fd220bb47b92c38eecde33e513bf66c3f861e78aebd21c37d88d14d8a0` | `mistralai/mistral-small-3.2-24b-instruct` |
| `sn76_3` | repositories | `phylax-repositories-independent` | 3 | `b53dc5de24f91d8295b438a1de0ca9be96a29651b87da8399cc80cf5fd9c5ff2` | `openai/gpt-4.1-mini` |
| `sn76_4` | repositories | `phylax-repositories-wave6` | 3 | `1974a01e1d0e7cb7154c5467e8930216dc35dfbcecf25917acc7cc355f43ebec` | `openai/gpt-4.1-mini` |

Server registry verification at approximately `2026-07-31T05:38Z` returned
`status=active`, `evaluated=false`, and `evaluation_state=pending` for every
row. The public names intentionally do not contain provider or model names.

Packages was initially accepted as version 3 under its stale local display
label. The label was corrected and the identical final SHA was accepted again
as version 4; version 4 is the active registry row.
