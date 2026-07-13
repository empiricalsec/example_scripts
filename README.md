# Empirical Tools

A home for Empirical Security tooling: reusable API clients plus runnable scripts.

## Layout

```
src/
  shared/                   cross-cutting utilities (HTTP retry, response/credential checks, env)
  empirical_client/         reusable client for the Empirical Security API
  qualys_client/            reusable client for the Qualys KnowledgeBase API
  scripts/
    qualys_empirical_join/  the join script (composes the two clients)
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

```sh
# verify credentials/connectivity first (nothing written)
uv run qualys-empirical-check

# small, fast run
uv run qualys-empirical-join --qualys-url https://qualysapi.qg2.apps.qualys.com --id-min 1 --id-max 5000

# full KnowledgeBase, filtered to recently-modified QIDs
uv run qualys-empirical-join --qualys-url https://qualysapi.qg2.apps.qualys.com --modified-after 2024-01-01
```

Key flags: `--qualys-url`, `--id-min` / `--id-max`, `--batch-size`,
`--modified-after` / `--modified-before`, `--published-after` / `--published-before`,
`--score-threshold` (default 70).

**Output** goes to `./output/` by default; change it with `--out-dir <path>`:

```sh
uv run qualys-empirical-join --qualys-url ... --out-dir /path/to/results
```

Three files are written to that directory:

- `results.json.gz` — one object per QID (`qid`, `title`, `matched_cves`, `matched_cve_count`)
- `results.csv` — one row per QID+CVE (`qid,title,cve,global_score`)
- `results.tar.gz` — the two files above plus `manifest.json` (run parameters + counts)

## Test

```sh
uv run pytest
```
