import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def ransomware_encryption_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Windows ransomware flow: macro -> shadow copy wipe -> encryption + ransom note."""
    shared = _shared_context(ctx)
    events = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "malicious_powershell_detect",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 1},
            "action": "blocked",
        },
    )
    evt1["process"] = {
        "pid": random.randint(3000, 7000),
        "name": "wscript.exe",
        "command_line": "wscript.exe C:\\Users\\Public\\invoice.js",
        "parent": {"name": "winword.exe", "command_line": "WINWORD.EXE /q /n"},
    }
    evt1["file"] = {
        "path": "C:\\Users\\Public\\invoice.js",
        "extension": "js",
        "size": random.randint(25000, 60000),
        "hash": {"sha256": _rand_hash()},
    }
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(20, 90),
        ctx,
        overrides={
            **shared,
            "category": "shellcode_detect",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 2},
            "action": "blocked",
        },
    )
    evt2["process"] = {
        "pid": random.randint(6000, 11000),
        "name": "vssadmin.exe",
        "command_line": "vssadmin delete shadows /all /quiet",
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(120, 240),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["file"] = {
        "path": "C:\\Users\\Public\\readme_for_decryption.txt",
        "extension": "txt",
        "size": random.randint(2000, 6000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["process"] = {
        "name": "encryptor.exe",
        "command_line": "encryptor.exe --threads 8 --paths C:\\Users",
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events
