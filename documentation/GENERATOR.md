# Generator Walkthrough

How the attack-chain generator produces NDJSON files, where the data comes from, and how the pieces fit together.

## Inputs & configuration
- Environment: `scripts/.env` (or shell env) controls `DB_PATH`, `OUTPUT_PREFIX`, `TARGET_EVENTS`, `BATCH_SIZE`, `ATTACK_CHAIN_RATIO`, `NOISE_RATIO`, and fallbacks for CSVs.
- Reproducibility: set `SEED` to seed Python’s RNG for deterministic draws.
- Summary: override `SUMMARY_PATH` to control where the run summary JSON is written (default `<OUTPUT_PREFIX>_summary.json`).
- Data sources:
  - SQLite alerts DB (`DB_PATH` or `DB_PATH_FALLBACK`) for IPs, ports, signatures, categories, severities, and protocol distributions.
  - AD users CSV (`AD_USERS_FILE`, default `/home/debian/ad_users.csv`).
  - CMDB assets CSV (`CMDB_ASSETS_FILE`, default `/home/debian/cmdb_assets.csv`).

## Context loading (`scripts/attack_chains/data_loader.py`)
- `load_context()` pulls distributions from the DB and merges AD users plus CMDB assets.
- Builds `ip_to_asset` to quickly map destination IPs to asset metadata.
- Returns:
  - weighted distributions: categories, severities, src/dest ports, protocols.
  - lists: source/destination IPs, signatures, AD users, assets.

## Base event construction (`scripts/attack_chains/builder.py`)
- `build_base_event(timestamp, ctx, overrides=None)` creates an ECS-like alert with:
  - Event metadata: severity (text + numeric in `fusionai.severity`), action/outcome, module/dataset.
  - Network: source/destination IPs/ports/bytes, protocol, direction.
  - User/host: AD user fields, asset fields, OS/platform, risk level.
  - Threat: MITRE tactic/technique mapped from category.
  - Rule/fusionai: signature/category IDs plus asset owner/location.
  - Tags/labels: basic env/source tagging.
- Optional `overrides` lets playbooks pin stage/sequence, category, severity, ports, IPs, and attach custom fields (process, file, registry, http, dns, etc.).

## Event generation orchestration (`scripts/attack_chains/generator.py`)
- `generate_events_to_disk()` flow:
  1. Loads context.
  2. Chooses a 30-day time window.
  3. Loops until `TARGET_EVENTS` reached:
     - With probability `NOISE_RATIO`, emit a low-severity benign/false-positive alert (`fusionai.noise=true`).
     - Else, with probability `ATTACK_CHAIN_RATIO`, generate a correlated chain; otherwise emit a standalone alert.
     - Accumulates events in memory until `BATCH_SIZE`, then writes NDJSON and starts a new batch.
 4. Prints throughput and file paths on completion.
 5. Persists a run summary (seed, observed ratios, counts, window, batches) to `SUMMARY_PATH`.

### Single-event path
- `_generate_single_event(ctx, start_ts, end_ts)`:
  - Picks random timestamp in window.
  - Calls `build_base_event`.
  - Adds light enrichment:
    - Powershell categories get a `process` with encoded `-enc`.
    - DGA categories get a random DNS A query.

### Attack-chain path
- `_generate_attack_chain(ctx, start_ts, end_ts)`:
  - Creates a unique `attack-{uuid}` ID and random chain start time.
  - Picks a playbook from `PLAYBOOKS`.
  - Returns a list of correlated events sharing users/assets/IPs and `attack.id`/`attack.stage`/`attack.sequence`.

## Playbooks (`scripts/attack_chains/playbooks/`)
- Each chain lives in its own module under the `playbooks` package and reuses shared helpers (`_shared_context`, `_append_and_maybe_stop`, `_rand_hash`, `_rand_domain`).
- `PLAYBOOKS` in `playbooks/__init__.py` aggregates all scenarios for the generator to pick from.
- Coverage spans cloud abuse, SaaS ATO, insider misuse, lateral movement variants, phishing/initial access, defense evasion, nuanced C2, staging/exfiltration, ransomware, and supply-chain/dev abuse. See `documentation/PLAYBOOKS.md` for a brief on each chain.

## Output
- Files: `OUTPUT_PREFIX####.json` (NDJSON batches), each line an event.
- Console logs show batch sizes and effective events/sec.
- Optional ingestion: use `scripts/inject_to_es.py` to load generated files into Elasticsearch (configure target ES/credentials in your env).

## Running it
- Execute: `python scripts/generate_attack_chains.py` (or invoke `generate_events_to_disk()` directly).
- Tune realism/performance with env vars:
  - Volume: `TARGET_EVENTS`, `BATCH_SIZE`.
  - Correlation vs. background noise: `ATTACK_CHAIN_RATIO`, `NOISE_RATIO`.
  - Data realism: `DB_PATH`, `AD_USERS_FILE`, `CMDB_ASSETS_FILE`.

> **Notes on observed ratios**
> - Ratios are evaluated per draw. Attack chains usually emit multiple documents (often 3+), so they consume a larger share of the final event count than the raw probability might imply.
> - Noise events are always singletons and generation stops once the size target is reached, so the observed noise percentage can trail the configured `NOISE_RATIO` slightly when the last batch overshoots the goal.
> - For exact event-level percentages, post-process the output (e.g., trim/append standalone alerts) or track draw counts instead of emitted events when reporting.
