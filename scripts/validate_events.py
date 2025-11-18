#!/usr/bin/env python3
"""Summarize generated NDJSON alerts for quick realism checks."""

import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from dotenv import load_dotenv

load_dotenv()


def _iter_event_files(paths: List[Path]) -> Iterable[Path]:
    for p in paths:
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if child.suffix in {".json", ".ndjson"} and child.is_file():
                    yield child
        elif p.is_file():
            yield p


def _parse_timestamp(value: str):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def summarize(paths: List[Path]) -> Dict[str, object]:
    category = Counter()
    severity_num = Counter()
    action_outcome = Counter()
    direction = Counter()
    users = set()
    hosts = set()
    chain_lengths: Dict[str, int] = defaultdict(int)
    t_min = None
    t_max = None
    total_events = 0
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
                    severity_num[str(sev_num)] += 1

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

                ts = evt.get("@timestamp")
                dt = _parse_timestamp(ts) if ts else None
                if dt:
                    t_min = dt if t_min is None or dt < t_min else t_min
                    t_max = dt if t_max is None or dt > t_max else t_max

    chains = list(chain_lengths.values())
    chain_stats: Tuple[int, int, float] = (0, 0, 0.0)
    if chains:
        chain_stats = (min(chains), max(chains), sum(chains) / len(chains))

    return {
        "files_processed": files_processed,
        "total_events": total_events,
        "categories": category,
        "severity_numeric": severity_num,
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
    }


def _print_counter(title: str, counter: Counter):
    print(f"{title}:")
    for k, v in counter.most_common():
        print(f"  {k}: {v}")
    if not counter:
        print("  (none)")


def main():
    parser = argparse.ArgumentParser(description="Validate/generated NDJSON metrics.")
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

    print(f"Files processed: {metrics['files_processed']}")
    print(f"Total events:    {metrics['total_events']}")
    print(f"Time range:      {metrics['time_range']['earliest']} -> {metrics['time_range']['latest']}")
    print(f"Unique users:    {metrics['unique_users']}")
    print(f"Unique hosts:    {metrics['unique_hosts']}")

    _print_counter("Categories", metrics["categories"])
    _print_counter("Severity (numeric/text)", metrics["severity_numeric"])
    _print_counter("Action/Outcome", Counter({f"{a}/{o}": c for (a, o), c in metrics["action_outcome"].items()}))
    _print_counter("Network direction", metrics["direction"])

    chains = metrics["chains"]
    print("Chains:")
    print(f"  attack ids: {chains['count']}")
    print(f"  events in chains: {chains['events_in_chains']}")
    print(f"  len min/avg/max: {chains['min_len']}/{chains['avg_len']}/{chains['max_len']}")


if __name__ == "__main__":
    main()
