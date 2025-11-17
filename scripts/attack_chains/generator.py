import json
import os
import random
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List

from .builder import build_base_event
from .data_loader import load_context
from .playbooks import PLAYBOOKS


def _choose_time_window(days: int = 30) -> (int, int):
    end_time = datetime.now()
    start_time = end_time - timedelta(days=days)
    return int(start_time.timestamp()), int(end_time.timestamp())


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


def generate_events_to_disk() -> None:
    """Generate standalone events and correlated attack chains to NDJSON files."""
    ctx = load_context()

    target_events = int(os.getenv("TARGET_EVENTS", "50000"))
    batch_size = int(os.getenv("BATCH_SIZE", "100000"))
    output_prefix = os.getenv("OUTPUT_PREFIX", "/home/debian/events_es_attack_chain_")
    chain_ratio = float(os.getenv("ATTACK_CHAIN_RATIO", "0.15"))  # fraction of events that belong to chains

    start_ts, end_ts = _choose_time_window(days=30)
    print(f"[+] Attack-chain generator :: events={target_events}, chain_ratio={chain_ratio}, window=30d")

    total_events = 0
    batch_num = 1
    batch_events: List[Dict[str, Any]] = []
    start_clock = time.time()

    while total_events < target_events:
        # Decide whether to create a chain or a single event
        if random.random() < chain_ratio:
            chain_events = _generate_attack_chain(ctx, start_ts, end_ts)
            for evt in chain_events:
                batch_events.append(evt)
                total_events += 1
                if total_events >= target_events:
                    break
        else:
            evt = _generate_single_event(ctx, start_ts, end_ts)
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
    print(f"[+] Done. events={total_events}, files={batch_num}, rate={rate:.0f} ev/s")
    print(f"[+] Files: {output_prefix}0001.json .. {output_prefix}{batch_num:04d}.json")


def _save_batch(batch_events: List[Dict[str, Any]], output_prefix: str, batch_num: int) -> None:
    filename = f"{output_prefix}{batch_num:04d}.json"
    with open(filename, "w") as f:
        for evt in batch_events:
            f.write(json.dumps(evt) + "\n")
    print(f"    wrote batch {batch_num:04d} -> {len(batch_events):,} events")
