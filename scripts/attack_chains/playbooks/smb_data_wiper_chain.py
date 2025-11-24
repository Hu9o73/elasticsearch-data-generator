import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def smb_data_wiper_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """SMB lateral movement ending in destructive wiping."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "malcore",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 1},
            "dest_port": 445,
            "direction": "internal",
            "action": "allowed",
        },
    )
    evt1["process"] = {
        "name": "psexec.exe",
        "command_line": f"psexec.exe \\\\{shared['dst_ip']} cmd.exe /c whoami",
    }
    evt1["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(30, 150),
        ctx,
        overrides={
            **shared,
            "category": "shellcode_detect",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "wevtutil.exe",
        "command_line": "wevtutil cl Security && wevtutil cl System",
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(200, 420),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 3},
            "action": "blocked",
        },
    )
    evt3["process"] = {
        "name": "cipher.exe",
        "command_line": "cipher.exe /w:C:\\Finance",
    }
    evt3["file"] = {
        "path": "C:\\Finance\\*.bak",
        "extension": "bak",
        "size": random.randint(5_000_000, 25_000_000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events
