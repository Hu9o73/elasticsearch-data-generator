# Noise & False Positives

Benign alerts are sprinkled in so dashboards feel closer to real SOC telemetry. Noise carries `fusionai.noise: true`, the `noise` tag, and `labels.noise_type` for easy filtering.

## Configuration
- `NOISE_RATIO` (in `scripts/.env`): probability any new event is noise instead of a true detection.
- Ratios are clamped between 0 and 0.95. If `ATTACK_CHAIN_RATIO + NOISE_RATIO` exceeds 0.95, both are scaled down to preserve headroom for baseline alerts.
- Seasonality (optional): set `NOISE_SEASONALITY=true` to bias noise toward business hours and maintenance windows (with a backup burst Sunday night). Use `NOISE_TZ_OFFSET` (hours) if you need to shift the window relative to the host clock.

## Standalone generator (`scripts/generate_events.py`)
- Picks a noise scenario when the random draw is under `NOISE_RATIO`, then builds an ECS-like event via `build_event()`.
- Scenarios: `dns_update` (Windows Update lookups), `internal_scanner` (vuln/compliance scan), `admin_login` (known admin Kerberos logon).

## Attack-chain generator (`scripts/attack_chains/generator.py`)
- Uses `_generate_noise_event()` under the same ratio rules, sharing context from the alerts DB/AD/CMDB.
- Scenarios: `dns_update`, `vuln_scanner`, `normal_login`, `approved_backup` (sanctioned cloud sync), `red_team_scan` (allowed pen test traffic). Each sets `fusionai.noise`, scenario labels, and adds enrichment (DNS question, scan metadata, file copy URL, or logon details).
- Optional seasonality will cluster benign logons/scans in weekday office hours and push backups/patchy traffic into late Sunday / early Monday, with lighter weekend daytime noise. If disabled (default), timestamps are uniform across the window.
- Noise events mix alongside standalone alerts and correlated playbooks so dashboards show realistic benign volume.

## Verification
`scripts/verify_es.py` aggregates `fusionai.noise` to show total count and percentage, plus chain coverage and severity mix. Run after ingestion to confirm observed ratios match configuration.
