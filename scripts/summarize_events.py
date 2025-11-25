#!/usr/bin/env python3
"""Pretty console resume of generated NDJSON alerts (chains, noise, seasonality)."""

import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()


# --------- IO helpers ----------
def _iter_event_files(paths: List[Path]) -> Iterable[Path]:
    for p in paths:
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if child.suffix in {".json", ".ndjson"} and child.is_file():
                    yield child
        elif p.is_file():
            yield p


def _parse_timestamp(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


# --------- Rendering ----------
def _bar(value: int, max_value: int, width: int = 32) -> str:
    if max_value <= 0:
        return ""
    fill = int((value / max_value) * width)
    fill = min(width, fill)
    return "#" * fill + "." * (width - fill)


def _print_section(title: str):
    print("\n" + title)
    print("-" * len(title))


def _fmt_pct(value: int, total: int) -> str:
    return f"{(value / total * 100):5.1f}%" if total else " 0.0%"


# --------- Main summarizer ----------
def summarize(paths: List[Path]) -> Dict[str, object]:
    category = Counter()
    chain_category = Counter()
    severity = Counter()
    action_outcome = Counter()
    direction = Counter()
    noise_by_hour = Counter()
    events_by_hour = Counter()
    users = set()
    hosts = set()
    chain_lengths: Dict[str, int] = defaultdict(int)
    chain_first_category: Dict[str, str] = {}
    t_min = None
    t_max = None
    total_events = 0
    total_noise = 0
    files_processed = 0

    for path in _iter_event_files(paths):
        files_processed += 1
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total_events += 1

                cat = evt.get("rule", {}).get("category") or evt.get("event", {}).get("module")
                if cat:
                    category[cat] += 1

                sev_num = evt.get("fusionai", {}).get("severity") or evt.get("event", {}).get("severity")
                if sev_num:
                    severity[str(sev_num)] += 1

                action = evt.get("event", {}).get("action", "unknown")
                outcome = evt.get("event", {}).get("outcome", "unknown")
                action_outcome[(action, outcome)] += 1

                net_dir = evt.get("network", {}).get("direction")
                if net_dir:
                    direction[net_dir] += 1

                user = evt.get("user", {}).get("name")
                if user:
                    users.add(user)

                host = evt.get("host", {}).get("hostname") or evt.get("host", {}).get("name")
                if host:
                    hosts.add(host)

                attack = evt.get("attack")
                if isinstance(attack, dict) and attack.get("id"):
                    chain_lengths[attack["id"]] += 1
                    if attack["id"] not in chain_first_category and cat:
                        chain_first_category[attack["id"]] = cat

                is_noise = evt.get("fusionai", {}).get("noise") is True
                if is_noise:
                    total_noise += 1

                ts = evt.get("@timestamp")
                dt = _parse_timestamp(ts) if ts else None
                if dt:
                    events_by_hour[dt.hour] += 1
                    if is_noise:
                        noise_by_hour[dt.hour] += 1
                    t_min = dt if t_min is None or dt < t_min else t_min
                    t_max = dt if t_max is None or dt > t_max else t_max

    for chain_id, first_cat in chain_first_category.items():
        chain_category[first_cat] += 1

    chains = list(chain_lengths.values())
    chain_stats: Tuple[int, int, float] = (0, 0, 0.0)
    if chains:
        chain_stats = (min(chains), max(chains), sum(chains) / len(chains))

    return {
        "files_processed": files_processed,
        "total_events": total_events,
        "categories": category,
        "chain_category": chain_category,
        "severity": severity,
        "action_outcome": action_outcome,
        "direction": direction,
        "unique_users": len(users),
        "unique_hosts": len(hosts),
        "chains": {
            "count": len(chain_lengths),
            "events_in_chains": sum(chains),
            "min_len": chain_stats[0],
            "max_len": chain_stats[1],
            "avg_len": round(chain_stats[2], 2),
        },
        "time_range": {
            "earliest": t_min.isoformat() if t_min else None,
            "latest": t_max.isoformat() if t_max else None,
        },
        "noise": {
            "total": total_noise,
            "ratio": (total_noise / total_events * 100) if total_events else 0.0,
            "by_hour": noise_by_hour,
        },
        "events_by_hour": events_by_hour,
    }


def _hourly_table(all_hours: Counter, noise_hours: Counter):
    max_all = max(all_hours.values()) if all_hours else 0
    print("Hour | All events (bar)                | Noise (bar)")
    print("-----+---------------------------------+----------------")
    for hour in range(24):
        all_val = all_hours.get(hour, 0)
        noise_val = noise_hours.get(hour, 0)
        bar_all = _bar(all_val, max_all)
        bar_noise = _bar(noise_val, max_all)
        print(f"{hour:02d}   | {bar_all:33s} {all_val:>6} | {bar_noise:16s} {noise_val:>6}")


def main():
    parser = argparse.ArgumentParser(description="Summarize generated NDJSON alerts with visual console output.")
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories containing NDJSON output. If omitted, uses OUTPUT_PREFIX env to locate files.",
    )
    args = parser.parse_args()

    targets: List[Path] = []
    if args.paths:
        targets = [Path(p) for p in args.paths]
    else:
        prefix = os.getenv("OUTPUT_PREFIX", "/home/debian/events_es_batch_")
        base = Path(prefix).expanduser()
        directory = base.parent
        stem = base.name
        glob_pattern = f"{stem}*.json"
        targets = list(directory.glob(glob_pattern))
        if not targets:
            raise SystemExit(f"No files found for OUTPUT_PREFIX={prefix}")

    metrics = summarize(targets)
    total_events = metrics["total_events"]

    print("=" * 72)
    print("FUSIONAI ALERT DATA RESUME")
    print("=" * 72)
    print(f"Files processed : {metrics['files_processed']}")
    print(f"Total events    : {total_events:,}")
    print(f"Time range      : {metrics['time_range']['earliest']} -> {metrics['time_range']['latest']}")
    print(f"Unique users    : {metrics['unique_users']:,}")
    print(f"Unique hosts    : {metrics['unique_hosts']:,}")

    _print_section("Chain coverage (playbooks)")
    chains = metrics["chains"]
    print(f"Attack chains   : {chains['count']:,} (events: {chains['events_in_chains']:,})")
    print(f"Chain len       : min {chains['min_len']} / avg {chains['avg_len']} / max {chains['max_len']}")
    if metrics["chain_category"]:
        top = metrics["chain_category"].most_common(8)
        max_val = top[0][1]
        for name, val in top:
            bar = _bar(val, max_val)
            pct = _fmt_pct(val, chains["count"])
            print(f"{name:<24} {bar} {val:>7} ({pct})")

    _print_section("Noise & seasonality")
    noise = metrics["noise"]
    print(f"Noise events    : {noise['total']:,} ({noise['ratio']:.1f}% of total)")
    _hourly_table(metrics["events_by_hour"], noise["by_hour"])

    _print_section("Top categories")
    if metrics["categories"]:
        top = metrics["categories"].most_common(12)
        max_val = top[0][1]
        for name, val in top:
            bar = _bar(val, max_val)
            pct = _fmt_pct(val, total_events)
            print(f"{name:<24} {bar} {val:>7} ({pct})")
    else:
        print("No categories found.")

    _print_section("Severity mix")
    if metrics["severity"]:
        max_val = max(metrics["severity"].values())
        for sev, val in sorted(metrics["severity"].items()):
            bar = _bar(val, max_val)
            pct = _fmt_pct(val, total_events)
            print(f"sev {sev:<3} {bar} {val:>7} ({pct})")
    else:
        print("No severity data.")

    _print_section("Action / outcome")
    if metrics["action_outcome"]:
        max_val = max(metrics["action_outcome"].values())
        for (action, outcome), val in metrics["action_outcome"].most_common(8):
            bar = _bar(val, max_val)
            pct = _fmt_pct(val, total_events)
            label = f"{action}/{outcome}"
            print(f"{label:<18} {bar} {val:>7} ({pct})")
    else:
        print("No action/outcome data.")

    _print_section("Network direction")
    if metrics["direction"]:
        max_val = max(metrics["direction"].values())
        for direction, val in metrics["direction"].most_common():
            bar = _bar(val, max_val)
            pct = _fmt_pct(val, total_events)
            print(f"{direction:<12} {bar} {val:>7} ({pct})")
    else:
        print("No direction data.")

    print("\nDone.")


if __name__ == "__main__":
    main()
