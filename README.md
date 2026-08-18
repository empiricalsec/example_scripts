# Empirical Tools

A home for Empirical Security tooling: reusable API clients plus runnable scripts.

## Layout

```
src/
  shared/                   cross-cutting utilities (HTTP retry, response/credential checks, env, email alerts, row-count validation)
  empirical_client/         reusable client for the Empirical Security API
  qualys_client/            reusable client for the Qualys VM/FO APIs (KnowledgeBase + Host Detection)
  scripts/
    qualys_empirical_join/  the join script (composes the two clients)
    simple_qid_posture_export/  one-row-per-QID posture export (highest global score, rounded)
tests/                      offline unit tests (HTTP mocked)
```

The `src/` tree keeps **reusable clients** and **shared utilities** separate from
**scripts**, so a new tool can import the clients without pulling in script-specific code.

## Setup

```sh
uv sync                     # install (editable) + test deps
```

Set the following environment variables before running (however you prefer to manage
them — shell export, `.env` loader, secrets manager, etc.). See `.env.example` for a
template.

- `EMPIRICAL_CLIENT_ID`
- `EMPIRICAL_CLIENT_SECRET`
- `QUALYS_USERNAME`
- `QUALYS_PASSWORD`
- `QUALYS_API_URL`

## Scripts

### `qualys-empirical-join`

Finds Qualys QIDs that have at least one CVE whose Empirical **Global model** score is
above a threshold (default 70), and writes the results as gzipped JSON, CSV, and a
tarball. Scoring uses Empirical's `global` scoring model (not an entity-specific model),
so results are consistent regardless of which entity's credentials are used.

The pipeline is Qualys-first: it pulls the org's QIDs (and their CVEs) from Qualys,
then fetches Empirical's complete `/api/cves/all` score export and narrows it to just
the CVEs those QIDs reference, so the report covers the full posture without relying
on large streamed `/api/search` responses.

#### QID sources (`--source`)

- **`detection`** (default) — the org's **live vulnerability posture**: the QIDs
  currently detected across assets, via the Host Detection API. Those QIDs are then
  mapped to CVEs through the KnowledgeBase (the KB remains the QID→CVE source; detections
  just decide *which* QIDs to resolve). Scope to specific asset group(s) with
  `--asset-group` (omit for the whole org).
- **`knowledge-base`** — scans the full KnowledgeBase over a QID id range
  (`--id-min`/`--id-max`), i.e. the entire vulnerability catalog rather than what's
  actually present in the environment.

```sh
# verify credentials/connectivity first (nothing written)
uv run qualys-empirical-check

# default: live org-wide posture
uv run qualys-empirical-join --qualys-url https://qualysapi.qg2.apps.qualys.com

# posture scoped to asset group(s), only active/new/re-opened detections
uv run qualys-empirical-join --asset-group "Prod Web" --asset-group "DB Tier" \
  --status "Active,New,Re-Opened"

# knowledge-base mode: a small QID window
uv run qualys-empirical-join --source knowledge-base --id-min 1 --id-max 5000

# knowledge-base mode: full catalog, filtered to recently-modified QIDs
uv run qualys-empirical-join --source knowledge-base --modified-after 2024-01-01
```

Key flags: `--qualys-url`, `--source` (`detection` | `knowledge-base`),
`--asset-group`, `--status` / `--severities` / `--show-igs` (detection mode),
`--id-min` / `--id-max` (knowledge-base mode), `--batch-size`,
`--modified-after` / `--modified-before`, `--published-after` / `--published-before`,
`--score-threshold` (default 70).

**Output** goes to `./output/` by default; change it with `--out-dir <path>`:

```sh
uv run qualys-empirical-join --qualys-url ... --out-dir /path/to/results
```

Three files are written to that directory, each name-stamped with the run's UTC
timestamp (e.g. `results-20260715T153045Z.json.gz`) so successive runs accumulate
instead of overwriting:

- `results-<stamp>.json.gz` — one object per QID (`qid`, `title`, `matched_cves`, `matched_cve_count`)
- `results-<stamp>.csv` — one row per QID+CVE (`qid,title,cve,global_score`)
- `results-<stamp>.tar.gz` — the two files above plus `manifest.json` (run parameters + counts)

### `simple-qid-posture-export`

Exports the org's **entire live vulnerability posture** as a compact CSV with
**one row per QID**. Each QID is scored with the **highest** Empirical Global
model score across its CVEs, **rounded to the nearest whole number** (0–100).
Unlike `qualys-empirical-join`, there is **no score threshold** — every detected
QID that maps to at least one scored CVE is included.

How it works:

1. Qualys **Host Detection** → the deduped set of QIDs currently detected across
   assets (scope with `--asset-group`; omit for the whole org).
2. Qualys **KnowledgeBase** → QID → \[CVE] mappings.
3. Empirical `/api/cves/all` export → the global score for **every** scored CVE,
   in a single gzipped download (no per-CVE calls, no cache needed).
4. Reduce to one `(qid, score)` row: `round(max score across the QID's CVEs)`.

QIDs whose CVEs are all unscored (or that have no CVEs) are omitted — there is no
score to report. The score column is the only value; a `last_updated_at` date is
intentionally **not** computed here — it's derived downstream (e.g. by diffing
successive daily runs of this export).

```sh
# whole-org posture
uv run simple-qid-posture-export --qualys-url https://qualysapi.qg2.apps.qualys.com

# scoped to asset group(s), only active/new/re-opened detections
uv run simple-qid-posture-export --asset-group "Prod Web" --status "Active,New,Re-Opened"
```

Key flags: `--qualys-url`, `--asset-group`, `--status` / `--severities` /
`--show-igs`, `--batch-size`, `--out-dir` (default `./output`),
`--min-rows` (default 500), `--alert-email-to` / `--alert-email-from`.

**Output**: a single UTC-stamped CSV, e.g. `qid-posture-20260721T153045Z.csv`,
with header `qid,score` (one row per QID, sorted by QID ascending).

#### Validation & email alerts

The export runs unattended, so it validates its own output size: a run that
writes **fewer than `--min-rows` rows** (default **500**, or `$MIN_ROWS`; set `0`
to disable) is treated as a failure — it's logged as an error and the process
**exits non-zero** so a scheduler flags it. The CSV is still written; validation
is a signal, not a gate.

Email alerts are **optional and off by default**. They're enabled purely by
configuring a recipient — set `$ALERT_EMAIL_TO` (or pass `--alert-email-to`,
repeatable/comma-separated). When enabled, a validation failure sends an email
via the host's **`mailx`**, so the host must have `mailx` installed with a working
mail setup (local MTA / relay). Optional: `$ALERT_EMAIL_FROM` /
`--alert-email-from` (passed as `mailx -r`) and `$ALERT_EMAIL_SUBJECT`. A mail
delivery failure is logged but never masks the validation failure. (`-r` is the
common BSD/macOS/RHEL `mailx` spelling; some variants differ.)

```sh
# alert oncall if the whole-org run comes back suspiciously small
ALERT_EMAIL_TO=oncall@example.com uv run simple-qid-posture-export \
  --qualys-url https://qualysapi.qg2.apps.qualys.com --min-rows 750
```

## Test

```sh
uv run pytest
```
