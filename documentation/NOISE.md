# Noise & False Positives

This document explains how the generators sprinkle benign alerts into the datasets so dashboards feel closer to real SOC telemetry.

## Configuration
- `NOISE_RATIO` (in `scripts/.env`): probability that any newly created event is noise instead of a true detection.
- The ratio is clamped between 0 and 0.95. If `ATTACK_CHAIN_RATIO + NOISE_RATIO` exceeds 0.95, both ratios are scaled down to leave headroom for regular single alerts.
- Noise events are tagged with `fusionai.noise: true`, the `noise` tag, and `labels.noise_type` so you can query or visualize them easily.

## Standalone generator (`scripts/generate_events.py`)
1. Each loop iteration rolls a random number and compares it to `NOISE_RATIO`.
2. When noise is selected, `generate_noise_event()` builds on the standard FusionAI distributions via the `build_event()` helper but overrides a few fields to mimic benign situations.
3. Scenarios currently emitted:
   - `dns_update`: outbound DNS A lookups for Windows Update domains.
   - `internal_scanner`: internal vulnerability/compliance scan traffic (looks like a port scan but marked as noise).
   - `admin_login`: successful Kerberos logons from known admins.
4. The generator updates counters so the summary footer shows how many noise alerts (and what percentage) were written.

## Attack-chain generator (`scripts/attack_chains/generator.py`)
- Uses `_generate_noise_event()` whenever the random draw falls under `NOISE_RATIO`.
- Each scenario reuses `build_base_event()` to stay ECS-compliant, then adds scenario-specific fields (DNS question, scanner metadata, or logon details).
- Noise events are mixed into the batches alongside standalone alerts and correlated playbook chains, sharing the same context sources (real IPs/users/assets).
- Completion logs print total noise volume and percent so you can verify the mix without inspecting Elasticsearch.

## Verification
`scripts/verify_es.py` aggregates `fusionai.noise` flags to show the total count and percentage of noise alerts, alongside chain coverage and severity mix. Run it after ingestion to confirm the observed ratios match your configuration.*** End Patch***```) to=functions.apply_patch ***!
