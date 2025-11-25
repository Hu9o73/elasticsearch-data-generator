import json
import os
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from .builder import build_base_event
from .data_loader import load_context
from .seasonal_noise import SeasonalNoiseModel
from .playbooks import PLAYBOOKS


def _clamp_ratio(value: float) -> float:
    return min(max(value, 0.0), 0.95)


def _choose_time_window(days: int = 30) -> (int, int):
    end_time = datetime.now()
    start_time = end_time - timedelta(days=days)
    return int(start_time.timestamp()), int(end_time.timestamp())


def _clamp_event_time(event: Dict[str, Any], start_ts: int, end_ts: int) -> Dict[str, Any]:
    """Ensure event @timestamp stays within the chosen window."""
    try:
        dt = datetime.fromisoformat(event["@timestamp"])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ts = int(dt.timestamp())
    except (KeyError, ValueError, TypeError):
        return event
    clamped_ts = min(max(ts, start_ts), end_ts)
    if clamped_ts != ts:
        event["@timestamp"] = datetime.fromtimestamp(clamped_ts, timezone.utc).replace(tzinfo=None).isoformat()
    return event


def _generate_single_event(ctx: Dict[str, Any], start_ts: int, end_ts: int) -> Dict[str, Any]:
    ts = random.randint(start_ts, end_ts)
    event = build_base_event(ts, ctx)

    # Light category-specific enrichment to keep variety
    category = event["event"]["module"]
    if "powershell" in category:
        encoded = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", k=60))
        event["process"] = {
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": f"powershell.exe -enc {encoded}",
        }
    if "dga" in category:
        domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(12, 18))) + ".com"
        event["dns"] = {"question": {"name": domain, "type": "A"}}

    return event


def _generate_attack_chain(ctx: Dict[str, Any], start_ts: int, end_ts: int) -> List[Dict[str, Any]]:
    attack_id = f"attack-{uuid.uuid4().hex[:10]}"
    chain_start = random.randint(start_ts, end_ts)
    playbook = random.choice(PLAYBOOKS)
    return playbook(ctx, attack_id, chain_start)


def _generate_noise_event(
    ctx: Dict[str, Any],
    start_ts: int,
    end_ts: int,
    seasonal: SeasonalNoiseModel = None,
) -> Dict[str, Any]:
    """Emit a benign/false-positive alert so dashboards contain realistic noise."""
    ts = seasonal.pick_timestamp(start_ts, end_ts) if seasonal else random.randint(start_ts, end_ts)
    scenario = seasonal.pick_scenario(ts) if seasonal else random.choice(
        ["dns_update", "vuln_scanner", "normal_login", "approved_backup", "red_team_scan"]
    )

    if scenario == "dns_update":
        overrides = {
            "category": "benign_dns_activity",
            "signature": "Windows Update DNS Lookup",
            "severity": "1",
            "action": "logged",
            "outcome": "success",
            "direction": "outbound",
        }
    elif scenario == "vuln_scanner":
        overrides = {
            "category": "false_positive_scan",
            "signature": "Internal vulnerability scanner",
            "severity": "2",
            "action": "blocked",
            "outcome": "failure",
            "direction": "internal",
        }
    elif scenario == "normal_login":
        overrides = {
            "category": "benign_user_activity",
            "signature": "Known admin login",
            "severity": "1",
            "action": "allowed",
            "outcome": "success",
            "direction": "internal",
        }
    elif scenario == "approved_backup":
        overrides = {
            "category": "benign_file_copy",
            "signature": "Approved data backup to cloud",
            "severity": "1",
            "action": "logged",
            "outcome": "success",
            "direction": "outbound",
        }
    else:
        overrides = {
            "category": "false_positive_scan",
            "signature": "Red team exercise",
            "severity": "2",
            "action": "logged",
            "outcome": "success",
            "direction": "internal",
            "dst_ip": random.choice(ctx.get("dest_ips", ["10.0.3.10"])),
        }

    event = build_base_event(ts, ctx, overrides=overrides)
    event["fusionai"]["noise"] = True
    event["tags"].append("noise")
    event["labels"]["noise_type"] = scenario

    if scenario == "dns_update":
        domain = f"windowsupdate.{random.choice(['microsoft.com', 'windows.com'])}"
        event["dns"] = {"question": {"name": domain, "type": "A"}}
        event["network"]["direction"] = "outbound"
    elif scenario == "vuln_scanner":
        event["fusionai"]["scan_type"] = "internal_compliance"
        event["fusionai"]["ports_scanned"] = random.randint(20, 200)
    elif scenario == "normal_login":
        event["logon"] = {"type": "network", "status": "success", "method": "kerberos"}
    elif scenario == "approved_backup":
        event["file"] = {
            "path": "/srv/shares/finance_approved_backup.zip",
            "extension": "zip",
            "size": random.randint(10_000_000, 30_000_000),
        }
        event["url"] = {"full": "https://backup.vendor.com/upload"}
        event["network"]["direction"] = "outbound"
    else:
        event["fusionai"]["scan_type"] = "red_team"
        event["network"]["direction"] = "internal"

    return event


def generate_events_to_disk() -> None:
    """Generate standalone events and correlated attack chains to NDJSON files."""
    seed = os.getenv("SEED")
    if seed is not None:
        try:
            random.seed(int(seed))
        except ValueError:
            random.seed(seed)
        print(f"[+] Seeded RNG with SEED={seed}")

    ctx = load_context()

    target_events = int(os.getenv("TARGET_EVENTS", "50000"))
    batch_size = int(os.getenv("BATCH_SIZE", "100000"))
    output_prefix = os.getenv("OUTPUT_PREFIX", "/home/debian/events_es_attack_chain_")
    chain_ratio = _clamp_ratio(float(os.getenv("ATTACK_CHAIN_RATIO", "0.15")))  # fraction in correlated chains
    noise_ratio = _clamp_ratio(float(os.getenv("NOISE_RATIO", "0.20")))  # fraction emitted as benign/noise alerts
    seasonal_noise = SeasonalNoiseModel()
    if chain_ratio + noise_ratio > 0.95:
        scale = 0.95 / (chain_ratio + noise_ratio)
        chain_ratio *= scale
        noise_ratio *= scale
        print(f"[!] Ratios adjusted to avoid starving baseline events (chain={chain_ratio:.2f}, noise={noise_ratio:.2f})")

    start_ts, end_ts = _choose_time_window(days=30)
    print(
        f"[+] Attack-chain generator :: events={target_events}, "
        f"chain_ratio={chain_ratio}, noise_ratio={noise_ratio}, window=30d, seasonal_noise={seasonal_noise.enabled}"
    )

    total_events = 0
    noise_events = 0
    chain_event_count = 0
    chains_built = 0
    batch_num = 1
    batch_events: List[Dict[str, Any]] = []
    start_clock = time.time()

    while total_events < target_events:
        # Decide whether to create a chain or a single event
        pick = random.random()
        if pick < noise_ratio:
            evt = _generate_noise_event(ctx, start_ts, end_ts, seasonal_noise)
            evt = _clamp_event_time(evt, start_ts, end_ts)
            batch_events.append(evt)
            total_events += 1
            noise_events += 1
        elif pick < noise_ratio + chain_ratio:
            chain_batch = _generate_attack_chain(ctx, start_ts, end_ts)
            chains_built += 1
            for evt in chain_batch:
                evt = _clamp_event_time(evt, start_ts, end_ts)
                batch_events.append(evt)
                total_events += 1
                chain_event_count += 1
                if total_events >= target_events:
                    break
        else:
            evt = _generate_single_event(ctx, start_ts, end_ts)
            evt = _clamp_event_time(evt, start_ts, end_ts)
            batch_events.append(evt)
            total_events += 1

        # Flush when batch size reached
        if len(batch_events) >= batch_size:
            _save_batch(batch_events, output_prefix, batch_num)
            batch_events = []
            batch_num += 1

    # Save any trailing events
    if batch_events:
        _save_batch(batch_events, output_prefix, batch_num)

    elapsed = time.time() - start_clock
    rate = total_events / elapsed if elapsed else 0
    chain_pct = (chain_event_count / total_events * 100) if total_events else 0
    noise_pct = (noise_events / total_events * 100) if total_events else 0
    print(
        f"[+] Done. events={total_events}, files={batch_num}, rate={rate:.0f} ev/s, "
        f"chains={chain_event_count} ({chain_pct:.1f}%), noise={noise_events} ({noise_pct:.1f}%), "
        f"built_chains={chains_built}"
    )
    print(f"[+] Files: {output_prefix}0001.json .. {output_prefix}{batch_num:04d}.json")

    summary = {
        "seed": seed,
        "target_events": target_events,
        "total_events": total_events,
        "chains_built": chains_built,
        "chain_events": chain_event_count,
        "noise_events": noise_events,
        "chain_ratio_effective_pct": round(chain_pct, 2),
        "noise_ratio_effective_pct": round(noise_pct, 2),
        "window_start": start_ts,
        "window_end": end_ts,
        "rate_eps": round(rate, 2),
        "batches": batch_num,
    }
    summary_path = os.getenv("SUMMARY_PATH", f"{output_prefix.rstrip('_')}_summary.json")
    try:
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Summary written to {summary_path}")
    except OSError as exc:
        print(f"[!] Failed to write summary {summary_path}: {exc}")


def _save_batch(batch_events: List[Dict[str, Any]], output_prefix: str, batch_num: int) -> None:
    filename = f"{output_prefix}{batch_num:04d}.json"
    with open(filename, "w") as f:
        for evt in batch_events:
            f.write(json.dumps(evt) + "\n")
    print(f"    wrote batch {batch_num:04d} -> {len(batch_events):,} events")
