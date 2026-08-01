# Repositories wave 12: real-CVE-derived vulnerable/fixed twins

## Scope and provenance

Wave 12 materialises eight compact behavioral fixtures in
`harness/repositories_wave12_realworld_trackcheck.py`. They are original
minimal reproductions rather than copies of upstream source. Each dangerous
case has a structurally close safe twin.

- FastChat [CVE-2024-10044](https://nvd.nist.gov/vuln/detail/CVE-2024-10044):
  request-controlled worker destination reaching a server-side HTTP request;
  negative twin resolves a user-selected name through an explicit trusted
  worker registry.
- gpt_academic
  [CVE-2024-10100](https://nvd.nist.gov/vuln/detail/CVE-2024-10100):
  URL-decoded request path reaching a file download; negative twin uses
  `secure_filename` under a fixed export root.
- Ragflow [CVE-2024-10131](https://nvd.nist.gov/vuln/detail/CVE-2024-10131):
  request-controlled model/factory selector chooses and instantiates an
  implementation class; negative twin rejects selectors outside an explicit
  allow-list.

Two adversarial controls harden those pairs: an allow-list comparison that
only logs and continues is still dangerous, and a `TRUSTED_*` registry stops
being a barrier after request-derived data is written into it.

The cases were selected from the confirmed findings published by
[VulnHuntr](https://github.com/protectai/vulnhuntr), then independently
cross-checked against NVD. The harness records the public CVE lineage in its
module documentation but contains no downloaded project code.

## Baseline gaps

| Gap | Independent | Wave-6 AST |
|---|---:|---:|
| Request-selected dynamic factory | missed | missed |
| Decoded path to `send_file` | missed | detected |
| Trusted registry used as outbound destination | false positive | false positive |
| Aggregate wave-12 score | `0.6333` | `0.8000` |

## Implementation

Both profiles now recognise request-controlled selection from registries whose
names carry model/factory/plugin/handler/provider/backend semantics, but emit
`CWE-94` only when the selected implementation is subsequently instantiated.
An explicit membership guard against an allowed/trusted/permitted/approved set
is a barrier.

Trusted fixed-destination registries are also modelled as sanitising lookups,
so a request-derived key does not incorrectly taint the constant internal URL
selected from the registry. The independent lexical profile additionally
tracks decoded path aliases into `send_file`.

The profiles remain independent: one uses bounded lexical assignments and call
confirmation; the other uses Python AST subscripts, taint slices, guards and
instantiation nodes.

## Validation

| Gate | Independent | Wave-6 AST |
|---|---:|---:|
| Wave 12 after | `1.0000` | `1.0000` |
| Structural suite + waves 3--11 | all `1.0000` | all `1.0000` |
| Adversarial repository LLM contract | passed | passed |
| Public upstream repository corpus | `1.0000` / eligible | `1.0000` / eligible |
| Python 3.11.15 sandbox import/report | passed | passed |
| Three-run determinism | passed | passed |

Validator-normalised similarity is `0.24156574052085808`, below the `0.92`
duplicate threshold.

## Submission receipts

Both validated profiles were accepted by both specialization endpoints on
2026-08-01 and independently confirmed through `GET /v1/agents`:

| Profile | Hotkey | Version | Active SHA-256 | Registry state |
|---|---|---:|---|---|
| `phylax-repositories-independent` | `sn76_3` | 8 | `66746d7568d134661d4e88628104dde64e9852a56118576f19791ea09839f6f0` | active / pending |
| `phylax-repositories-wave6` | `sn76_4` | 8 | `c21105736eeea439c7e7cd8f8be5b7933adb1d15e81ab92e7ee073e2655ef547` | active / pending |

The accepted agent IDs remain `ab89e82868f341b8babdee9ff5de70f3`
and `a98faa7507024a2284f1dd04414c6dad`, respectively. These receipts confirm
registry acceptance; validator evaluation has not run yet.

## Next isolated leverage

The next real-pair layer should use exact vulnerable and fixing commits from
ReposVul/CVEfixes for multi-file authorization/state bugs and store their
repository, commit, path, line, CWE and licence provenance in a machine-readable
manifest. That is intentionally separate from this small confirmed-CVE seed
layer so label corrections do not silently change detector behavior.
