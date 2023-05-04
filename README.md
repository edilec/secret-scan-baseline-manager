# Secret Scan Baseline Manager

Read-only checker for local scanner-result and approval-baseline exports. It never scans source, stores secret matches, or rewrites a baseline. Node.js 22+, zero dependencies. `src/index.mjs` exports `auditBaseline(scanner, baseline, policy, {now, deadline})` and `TOOL_ID`.

```sh
node bin/secret-scan-baseline-manager.mjs --root examples --policy policy.json --scanner scanner.json --baseline passing-baseline.json
node bin/secret-scan-baseline-manager.mjs --root examples --policy policy.json --scanner scanner.json --baseline failing-baseline.json
```

The synthetic examples exit 0 and 1. `--help` prints usage to stderr; normal runs print a bounded human summary to stderr. Stdout contains only the v1 JSON report.

## Input and approval model

Policy is `{"schemaVersion":"1","asOf":"2026-09-26T00:00:00Z"}`. Scanner export is `{"schemaVersion":"1","complete":true,"scannedFiles":3,"findings":[{"fingerprint":"<64 lowercase hex>","ruleId":"synthetic-pattern","file":"src/example.txt","line":12}]}`. Baseline is `{"schemaVersion":"1","complete":true,"entries":[{"fingerprint":"<same>","ruleId":"synthetic-pattern","file":"src/example.txt","line":12,"owner":"team-a","reason":"synthetic test waiver","expiresAt":"2026-10-01T00:00:00Z"}]}`. No raw match text is allowed in either schema. A baseline approves **only** the exact fingerprint, rule, relative file, and line; reappearance elsewhere is a new finding even with the same fingerprint. Approval owner and reason must be usable, and expiry must be later than declared `asOf`. Duplicate exact scopes are ambiguous. An unmatched baseline is stale when a scanner export declares complete coverage. A complete empty scan can pass only with `scannedFiles > 0` and no stale baseline entries. The checker trusts the scanner's `complete` and `scannedFiles` assertions; it cannot independently verify scanner coverage.

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| policy-invalid | warning | invalid policy (CLI rejects configuration) |
| scanner-invalid | warning | scanner finding or export shape invalid |
| baseline-invalid | warning | baseline entry/export shape invalid or duplicate |
| export-incomplete | warning | scanner or baseline declares partial coverage |
| scan-empty | warning | no scanned-file coverage asserted |
| limit-exceeded | warning | byte, count, depth, or time bound exceeded |
| input-unreadable | warning | export unreadable, undecodable, or unparseable |
| new-finding | error | scanner scope has no exact approval |
| exception-expired | error | exact approval expired |
| approval-owner-missing | error | approval owner absent or unusable |
| approval-reason-missing | error | approval reason absent or unusable |
| stale-baseline | error | approval scope absent from complete scan |

Reports sort by code-unit `(location.file, location.pointer, ruleId)` and use fixed logical roles `@scanner`, `@baseline`, `@policy`, not host paths. JSON pointers have zero-based finding/entry ordinals to locate evidence in the invoked file. No fingerprints, file names, matched text, owners, or reasons are emitted. Exit 0 pass, 1 completed policy failure, 2 incomplete evidence/configuration. Invalid usage, path, root, or policy leaves stdout empty; unreadable or ambiguous scanner/baseline input emits an incomplete JSON report. Inputs must be relative and realpath-confined beneath the declared root.

Limits: policy ≤64 KiB; each export ≤1 MiB; ≤10000 scanner findings and ≤10000 baseline entries; JSON depth ≤16; injected deadline 5 seconds. UTF-8 decoding is strict; duplicate JSON object keys, including escaped aliases, are rejected. A bound breach is incomplete, never truncated. Fingerprints can be guessable hashes of low-entropy secrets: keep exports access-controlled, and never use the report to disclose or query a fingerprint. Only synthetic fingerprints and examples are shipped here. Run `npm run check` for syntax and tests.
