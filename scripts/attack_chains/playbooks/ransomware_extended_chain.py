import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def ransomware_extended_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Ransomware: shadow copy removal, backup wipe, GPO abuse, encryption, ransom note."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "ransomware_extended",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 1},
            "action": "blocked",
        },
    )
    evt1["process"] = {"name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all /quiet"}
    evt1["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(300, 900),
        ctx,
        overrides={
            **shared,
            "category": "backup_wipe",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 2},
            "action": random.choice(["blocked", "logged"]),
        },
    )
    evt2["process"] = {"name": "robocopy.exe", "command_line": "robocopy \\\\backup01\\shares \\\\backup01\\shares /MIR"}
    evt2["file"] = {"path": "\\\\backup01\\shares\\*.bak", "extension": "bak", "size": random.randint(10_000_000, 50_000_000)}
    evt2["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(1200, 2100),
        ctx,
        overrides={
            **shared,
            "category": "gpo_abuse",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["process"] = {
        "name": "powershell.exe",
        "command_line": "Set-GPRegistryValue -Name DisableRecovery -Key HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Backup -ValueName DisableRecovery -Type DWORD -Value 1",
    }
    evt3["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1800, 2600),
        ctx,
        overrides={
            **shared,
            "category": "ransomware_extended",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 4},
            "action": "logged",
        },
    )
    evt4["process"] = {"name": "locker.exe", "command_line": "locker.exe --encrypt C:\\Users --threads 6"}
    evt4["file"] = {"path": "C:\\Users\\Public\\locked_file.docx.locked", "extension": "locked"}
    evt4["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt4):
        return events

    evt5 = build_base_event(
        start_ts + random.randint(2200, 3200),
        ctx,
        overrides={
            **shared,
            "category": "ransomware_extended",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 5},
            "action": random.choice(["blocked", "logged"]),
        },
    )
    evt5["file"] = {
        "path": "C:\\Users\\Public\\README_RESTORE.txt",
        "extension": "txt",
        "size": random.randint(2000, 7000),
    }
    evt5["process"] = {"name": "locker.exe", "command_line": "locker.exe --write-note --tor http://abcdonion.onion"}
    evt5["network"]["direction"] = "outbound"
    _append_and_maybe_stop(events, evt5)

    return events
