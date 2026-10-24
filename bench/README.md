# Public benchmark: sqli-scanner vs sqlmap

This directory holds a **small, reproducible cross-tool benchmark** on a **third-party**
target (DVWA). It answers one narrow question:

> On the same DVWA endpoints, do we and sqlmap reach the same vulnerable/safe conclusion?

It does **not** produce a general detection rate. The sample is 5 cases. Treat it as a
sanity check and a starting point, not a marketing number.

## Why DVWA

- Official source, not written by this project.
- The safe side is guaranteed by upstream code: `impossible` uses PDO prepared statements
  plus `is_numeric`, while `low` concatenates the parameter into SQL.
- It is PHP + MySQL/MariaDB, complementing the SQLite-based external judges
  (Juice Shop, VAmPI).

The older `e2e/sqlmap-benchmark/run.mjs` (23 levels on a self-written sqli-labs replica)
is still useful as a same-question control, but its truth is self-authored. This benchmark
exists to add an external-truth comparison.

## Cases

| id | method | endpoint | level | expected |
|---|---|---|---|---|
| `dvwa-get-low` | GET | `/vulnerabilities/sqli/?id=1` | low | vulnerable |
| `dvwa-post-medium` | POST | `/vulnerabilities/sqli/` (`id=1&Submit=Submit`) | medium | vulnerable |
| `dvwa-blind-low` | GET | `/vulnerabilities/sqli_blind/?id=1` | low | vulnerable |
| `dvwa-safe-impossible` | GET | `/vulnerabilities/sqli/?id=1` | impossible | safe |
| `dvwa-safe-blind-impossible` | GET | `/vulnerabilities/sqli_blind/?id=1` | impossible | safe |

Both tools run with detection settings only:

- our engine: `level=2`, `risk=1`, one thread, techniques `union/error/boolean/time/stacked`
- sqlmap: `--level=2 --risk=1 --threads=1 --technique=BEUSTQ --no-cast`
- sqlmap version is recorded in `summary.json` (expected: 1.10.7)

Each case can be repeated (`--runs=N`): detection is majority-vote, time is median,
techniques are the union of hit runs. Use `--runs=3` when publishing numbers.

## Run

1. Start the target:

```bash
# Windows dev machine used by this repo (MariaDB + DVWA on :8099)
node scripts/labs.mjs --up=mariadb,dvwa
node scripts/labs.mjs --check
```

Alternatively, use the official DVWA container (`digininja/dvwa`) and point
`DVWA_BASE` at it. Pin the image tag/digest you used.

2. Ensure `sqlmap` is on `PATH` (or set `SQLMAP_BIN`).

3. Run:

```bash
npm run bench:sqlmap -- --runs=3
# or: node bench/run.mjs --runs=3 --strict
```

Outputs land in `bench/results/<timestamp>/` (gitignored):

- `summary.md` — table + caveats
- `summary.json` — machine-readable, including tool versions and optional DVWA source hashes
- `raw/sqlmap-<case>-run<N>.txt` — raw sqlmap output

`--strict` makes the process exit 1 if **our** engine has a false negative or false positive;
the default always exits 0 after a completed run, because a benchmark result is data, not a gate.

If DVWA or sqlmap is missing, the runner prints `[SKIP]` and exits 0. It never fabricates a
comparison.

## Evidence rules

- Safe cases with fewer than 30 requests from our engine are marked **evidence insufficient**
  and are not counted as true negatives. A short scan that finds nothing is not proof of safety.
- sqlmap output is classified only from `Type:` lines, never from a bare "might be injectable"
  heuristic line.
- Times are wall-clock under each tool's own request strategy; they are not per-request costs.

## Recorded results

See `bench/results/<timestamp>/summary.md` for the latest local run. A tracked summary with
environment and caveats can be added under `docs/benchmarks/` when a result is published.
