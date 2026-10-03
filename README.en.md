# sqli-scanner

[![CI](https://github.com/fengxingxuerong/sqli-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/fengxingxuerong/sqli-scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**English** | [简体中文](README.md)

> One-command SQL injection detection that produces a **delivery-grade report** and a **CI exit code**.
> Web UI · CLI · desktop app. No command-line flags required to get a first result.

---

## Why this exists

Most SQL injection tooling is built for one audience: an operator sitting at a terminal.
This tool is built for two at the same time.

| Audience | What they get |
|---|---|
| An operator | Paste a URL, click start, read a report in the browser. Or one CLI command that writes a full report bundle to disk. |
| A CI pipeline | Machine-readable artifacts (JSON / SARIF) plus a meaningful exit code, so a scan can gate a build. |

The second audience is the one existing tools under-serve. `sqlmap` is an excellent *exploitation* tool;
it is not a *delivery* tool — it prints to a terminal and has no SARIF output, no CVSS scoring,
and no stable exit-code contract.

---

## Quick start

### Web UI

```bash
npm install
cd server && npm install && cd ..

npm run server     # terminal 1 — backend on :4567
npm run dev        # terminal 2 — frontend on :5173
```

Open <http://localhost:5173>.

### Docker

```bash
SCAN_API_TOKEN=$(openssl rand -hex 32) docker compose up -d
# frontend + API both on http://localhost:4567
```

The engine can scan and dump arbitrary reachable targets, so the deployment default is
**fail-closed**: binding to a non-loopback address without `SCAN_API_TOKEN` refuses to start
instead of exposing an unauthenticated scanner.

### One-command scan (CLI)

No server required. Validates the target, scans, writes a full report bundle, and emits an
exit code you can gate CI on (`0` clean / `2` Critical or High found / `1` run failure).
A ready-to-copy GitHub Actions workflow with SARIF upload lives in
[`docs/CI-集成.md`](docs/CI-集成.md) (Chinese).

```bash
node scripts/one-click-scan.mjs -u "http://target/page?id=1"
```

Output lands in `reports/<host>-<timestamp>/`:

| File | Purpose |
|---|---|
| `report.html` | Human-readable deliverable (executive summary, findings, PoC, remediation, WAF engagement log) |
| `report.json` | Complete machine-readable report, including per-finding PoC evidence |
| `report.md` | Markdown deliverable, pastes straight into a ticket or wiki |
| `report.sarif` | SARIF 2.1.0 for GitHub Security / DefectDojo (`--formats` must request it) |
| `report.csv` | Findings + dumped rows, opens in Excel (`--formats` must request it) |
| `manifest.json` | Structured manifest: metadata, finding index, file list, authorization statement |

Exit codes: `0` no high-severity findings · `2` critical or high found · `1` execution failure.

---

## Report contents

Every finding carries the five elements needed to act on it, and all output formats are rendered
from a single source of truth — there is no "field present in HTML but missing from Markdown" drift.

| Element | Field |
|---|---|
| Vulnerability type | `vulnType.nameZh` / `nameEn` / `cwe` / `owasp` |
| Risk | `riskLevel` + CVSS v3.1 (`score` / `vector` / `severity`) |
| Affected parameter | `param` / `location` / `affectedParam` / `url` / `method` |
| Proof of exploit | `poc.curl` / `poc.raw` / `poc.payload` |
| Remediation | Channel-specific guidance plus a general hardening baseline |

The affected-parameter fields are written back onto the finding itself, so a report remains
readable after it has been detached from the original scan JSON.

When credentials are dumped (`--passwords`), the report gains a **credential-risk** section. Each
account's hash is identified by **format only** (MySQL native / caching_sha2, PostgreSQL md5 /
SCRAM-SHA-256, SQL Server `0x0100` / `0x0200`, bcrypt / argon2, and the like), labelled by strength
and flagged when weak. Identification is entirely offline — no cracking, no networking — and the
raw hash is never echoed into the report.

---

## What it detects

| Technique | Type | CWE |
|---|---|---|
| `union` | UNION-based, reads tables directly through an echo position | CWE-89 |
| `error` | Error-based extraction plus DBMS fingerprinting | CWE-89 |
| `boolean` | Boolean-blind inference from content differences | CWE-89 |
| `time` | Time-blind inference, works without content differences | CWE-89 |
| `stacked` | Stacked queries — writes and stored procedures | CWE-89 |
| `oob` | Out-of-band DNS/HTTP callback carrying data out | CWE-89 |
| `second_order` | Write point and trigger point separated (supports cross-role identities) | CWE-89 |
| `inline` | Derived tables and subquery contexts | CWE-89 |
| `nosql` | User input merged into a query object (`$where`, operators) | CWE-943 |

Anything not covered by the taxonomy is never silently classified — it falls back to a
dictionary type and is marked for manual review in the report.

---

## Supported databases — by evidence tier

Counts are deliberately not stated here. What matters is **how strong the evidence is**, and the
tier of every dialect is maintained in one place in the code (`server/src/engine/dbmsEvidence.js`)
and written into each report's `summary.dbmsEvidence`. You can judge a conclusion's reliability
without consulting this file.

| Tier | Dialects | Evidence |
|---|---|---|
| **Verified** | MySQL, MariaDB, PostgreSQL, SQLite, Oracle, SQL Server | Full detection/bypass path exercised against a real engine instance |
| **Partial** | H2, HSQLDB, Derby | Boolean channel verified against real JDBC engines. Detection works under a default-mode CRS deployment, but **database identification does not complete**. Do not read this as "bypasses any WAF". |
| **Template only** | TiDB, DM8, ClickHouse, DB2, Sybase, Firebird, Informix, Access, MonetDB | Dialect templates exist; syntax, column types and error text are unverified. Treat findings as **leads, not evidence**. |

The report states this caveat automatically in `summary.dbmsEvidence.caveat`.

---

## Injection points

- **Default scope**: same-origin as the target. Anything out of scope is refused **before any request is sent**.
- **Redirects**: every hop is re-validated against the authorized scope — a 302 to an unauthorized host stops the scan.
- **SSRF**: private, loopback, link-local and cloud-metadata addresses are denied by default. Authorized internal targets require an explicit opt-in.
- **Locations**: query and body by default, including nested JSON (`user.id`, `tags.0`) and XML/SOAP leaf paths. Request headers and path segments are opt-in.
- **Request import**: Burp XML, HAR, Postman collections and OpenAPI JSON are accepted as batch input, plus `-r` for a single raw request.

Target authentication: Basic, Digest, NTLM (self-implemented DES, no legacy OpenSSL flag needed), and mTLS client certificates.

---

## WAF handling

- A tamper plugin library covering **sqlmap's entire upstream tamper set**. Parity against the
  upstream tag is enforced by `npm run tamper:parity`, so the claim cannot silently rot.
- A WAF fingerprint library that recommends tamper chains for the detected product.
- An in-repo CRS rule executor, pinned against the **official CRS regression corpus** —
  fidelity is a gated number, not an assertion.

### Honest boundary: what the WAF numbers do and do not mean

This is the part most projects leave out.

- Against a **real ModSecurity + CRS container**, the measured result is that tamper chaining
  **breaches the WAF and executes SQL** for **one** plugin. Many more chains are merely *allowed
  through* — "allowed through" and "breached" differ by roughly an order of magnitude, and that
  gap is measured, not estimated.
- **No bypass rate is published.** The denominator is too small to be statistically meaningful.
  Any number you see elsewhere attributed to this project's WAF bypass rate should be treated as invalid.
- The CRS fidelity figure covers **query and form body only**. Most rules in the relevant CRS
  family declare they read `XML:/*`, and this executor does not parse XML — so the fidelity
  number must not be extrapolated to XML endpoints.
- Out-of-band UNC/SMB vectors (MySQL/MariaDB `LOAD_FILE`, SQL Server `xp_dirtree`) require an
  external SMB listener; the bundled receiver only listens on HTTP and DNS.

---

## How the claims are verified

You do not have to take any of this on faith. Every factual claim in this repository is backed by
a command.

```bash
npm test                                   # frontend suite
cd server && npm test                      # backend suite
npm run acceptance                         # 17-suite end-to-end gate
npm run mutation                           # mutation gate: does a broken mutant make a test fail?
npm run perf:budget                        # request-cost measurement, no network needed
npm run facts:check                        # README figures vs. freshly collected facts
npm run readme:check                       # README claims vs. code single sources of truth
npm run artifact:drift                     # committed e2e baselines vs. current code
```

The acceptance gate **does not trust any suite's self-reported `PASS` string**. It parses
independently checkable facts — number of vulnerable scenarios detected, number of false
positives on safe controls, files that actually exist — and derives the exit code from those.

That discipline exists because coverage is not effectiveness. The failure modes this project
hunts are the ones where an intermediate layer reports success and nobody checks the outside:
`wrote: true` with no file on disk, a probe sent with no closure, a scorecard that printed
"detected" for five days while both measurement columns were empty.

Several conclusions previously published here have since been **retracted by this same gate**.
Those retractions are documented in `docs/` rather than quietly deleted — see
[`docs/waf-绕过能力实测口径.md`](docs/waf-绕过能力实测口径.md) for the clearest example:
a fidelity fix from 60.7% to 99.3% inverted the entire conclusion set.

---

## Where the numbers live

Figures such as test counts, coverage and capability totals are **not repeated in this file**.
They are published in [`README.md`](README.md) (Simplified Chinese), where they are collected by
`npm run facts:refresh` from an actual test run and verified on every CI run by `npm run facts:check`.
Duplicating them here would create a second declaration site that nothing checks — which is
exactly the class of defect this project spends most of its engineering effort eliminating.

---

## Repository layout

```
frontend/   React + TypeScript + MUI + Vite
    ↓ REST + SSE
backend/    Express + Node.js
    ├── engine/   detection engine (detectors, extractor, exploiter)
    ├── core/     tamper / WAF / DB drivers / OOB receiver / HTTP client
    └── api/      routes (scan / exploit / tamper / health)
desktop/    Tauri shell (one-time token handshake with the engine sidecar)
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — project structure, development environment, code
conventions, engine architecture notes, and commit rules. (Written in Chinese.)

## License

[MIT](LICENSE)
