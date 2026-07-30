# Repositories wave 6 — request-flow coverage

Wave 6 extends the standalone repositories agent with narrow source-to-sink
rules for request-controlled data. It replaces wave 5 on `sn76_4`; it is not
reused for the independent `sn76_3` candidate.

## Added coverage

- Java `ObjectInputStream` request deserialization (`CWE-502`);
- Ruby `Marshal.load` request deserialization (`CWE-502`);
- direct request-controlled URL fetches in PHP and Java (`CWE-918`);
- request-controlled Ruby ERB templates (`CWE-1336`);
- request-controlled Go template parsing (`CWE-1336`).

Each rule has a malicious and benign twin. All six malicious cases score
`1.0000`, and all six benign cases remain clean.

## Regression gate

- repository structural suite: `0.7275`;
- repository precision suite: `0.8250`;
- wave 3: `0.7275`;
- wave 4: `0.7022`;
- wave 5: `0.6986`;
- wave 6: `0.6950`;
- public corpus: `0.7600`;
- expanded corpus: `0.8372`;
- Docker reference preflight: import, report contract and 3-run determinism
  passed on Python 3.11.15.

Source and deploy SHA-256:

```text
09ded08564b767df5d834bd725049ff22785ad5b4ab99e4e9bcfeb8bba7732b6
```

## Submission receipt

- wallet hotkey: `sn76_4`
- hotkey: `5EjmzJs6rKhka6CrgQbEa72aFzjuwwETBwGRQLpTMuHAigmi`
- label: `phylax-repositories-wave6`
- agent ID: `a98faa7507024a2284f1dd04414c6dad`
- version: `2`
- server status: `active`
- created at: `2026-07-30T18:16:39.555999`
- submitted SHA-256:
  `09ded08564b767df5d834bd725049ff22785ad5b4ab99e4e9bcfeb8bba7732b6`
- next-round eligibility: `true`
- eligibility state: `new`
- server reason: `first round for this hotkey`

The specialization registration and agent upload both returned HTTP 200.
