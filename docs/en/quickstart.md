# Quick start (English)

This is the short, task-oriented guide. The deeper references are in Chinese under
[`docs/`](../) (API, acceptance, WAF evidence, release process); commands and report
formats are language-neutral.

## Requirements

- Node.js **>= 20** (Node 24 is what CI uses)
- Optional: Docker / Docker Compose for the container form
- Optional: a database lab if you want to run the acceptance suite

The engine has **no runtime npm dependencies** of its own. The HTTP server and database
drivers live in `server/` and are installed separately.

## Install from source

```bash
npm install
cd server && npm install && cd ..
npm run build          # produces dist/ (the server serves it at :4567)
```

Run the web panel:

```bash
cd server && node index.js
# http://127.0.0.1:4567
```

`HOST` defaults to loopback. Binding to a non-loopback address requires `SCAN_API_TOKEN`
(the server refuses to start otherwise).

## One-command CLI scan

No server required. Reports are written to `reports/<host>-<timestamp>/`.

```bash
node scripts/one-click-scan.mjs -u "http://target/page?id=1"
# equivalent: npm run scan -- -u "http://target/page?id=1"

# request extra machine-readable formats
node scripts/one-click-scan.mjs -u "http://target/page?id=1" \
  --formats html,json,markdown,sarif,csv
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | No Critical/High findings |
| `2` | Critical or High finding present |
| `1` | Execution failure (invalid target, authentication lost, etc.) |

Read `summary.verdict` before quoting a result. `inconclusive` / `session_expired` is **not**
"no vulnerability found". Also check `summary.unverifiedSurfaces` (could not be tested) and
`summary.uncoveredSurfaces` (not covered by the current level/flags).

## CI (GitHub Actions)

`action.yml` is a composite action; the repository must be checked out by the caller.

```yaml
- uses: actions/checkout@v4
- uses: your-org/sqli-scanner@v1.2.1
  with:
    target: https://staging.example.com/item?id=1
    formats: sarif
    authorization: "authorized by <ticket>"
```

Upload the SARIF file with `github/codeql-action/upload-sarif` and keep
`security-events: write`. See `docs/CI-集成.md` (Chinese) for a full workflow.

## REST API

```bash
export SCAN_API_TOKEN="$(openssl rand -hex 32)"   # required for non-loopback binding
cd server && node index.js

curl -s -X POST http://127.0.0.1:4567/api/scan/start \
  -H "Authorization: Bearer $SCAN_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"url":"http://target/page?id=1"}'
```

Minimal loop: `POST /api/scan/start` → `GET /api/scan/:id/events` (SSE; token via query) →
`GET /api/scan/:id/report[/export?format=json|html|markdown|sarif|csv]`.
Full endpoint table: `docs/api.md`.

## MCP (AI agent hosts)

```json
{ "command": "node", "args": ["<repo>/server/bin/cli.js", "mcp"] }
```

Nine tools: `run_scan`, `get_scan_status`, `get_findings`, `get_report`, `list_scans`,
`stop_scan`, `pause_scan`, `resume_scan`, `preflight`. MCP uses the same sanitize/SSRF/scope
guards as REST; `risk=3` still requires an explicit `confirmDestructive=true`.

## Docker

Build locally:

```bash
SCAN_API_TOKEN=$(openssl rand -hex 32) docker compose up -d
# http://localhost:4567
```

On a version tag, CI publishes a Linux/amd64 image to
`ghcr.io/fengxingxuerong/sqli-scanner:<version>` (see
[`docs/release-process.md`](../release-process.md)). Pulling requires a published tag.

## Prebuilt desktop artifacts

Tag builds produce:

- `sqli-v<version>-portable-win32-x64.zip` — unpack and run `sqli-scanner.exe`
- `*-setup.exe` — NSIS installer (requires the Windows runner to download the NSIS toolchain)
- `SHA256SUMS.txt` and CycloneDX SBOMs attached to the GitHub Release

macOS/Linux desktop builds are not part of the current release gate.

## Safety and authorization

- Only scan systems you are explicitly authorized to test.
- Private/loopback targets are blocked by SSRF protection by default; set
  `SSRF_ALLOW_PRIVATE=1` only for your own lab.
- `--risk 3` requires `--confirm-destructive`.
- Exploitation (`--sql-shell`, `--os-shell`, file read/write, dumping) requires
  `EXPLOIT_ENABLED=1` **and** `--authorized`.

## Known scope limits

- 6 DBMS have full real-engine verification; 3 have partial channel verification;
  9 are template-only adapters (see the layered table in the Chinese README).
- Commercial cloud WAF samples are not yet collected; WAF claims are scoped to
  ModSecurity/CRS and the in-repo executor.
- Docker is amd64-only for now; arm64 is not verified.
- Windows code signing / macOS notarization are not set up.

## Verifying a checkout

```bash
npm run gate:close        # 27-item local closure gate
npm run acceptance        # 25 suites; needs lab services (see scripts/labs.mjs)
npm run release:check     # version/tag/Tauri consistency
```
