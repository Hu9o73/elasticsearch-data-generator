import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def kerberos_golden_ticket_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Detectable flow for Kerberos ticket forgery and lateral movement."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "shellcode_detect",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 1},
            "action": "blocked",
        },
    )
    evt1["process"] = {
        "name": "mimikatz.exe",
        "command_line": 'mimikatz "privilege::debug" "lsadump::lsa /inject"',
    }
    evt1["file"] = {
        "path": "C:\\Temp\\krbtgt.dmp",
        "extension": "dmp",
        "size": random.randint(500000, 1500000),
        "hash": {"sha256": _rand_hash()},
    }
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(20, 120),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "privilege_escalation", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "klist.exe",
        "command_line": "klist tgt",
    }
    evt2["logon"] = {"type": "network", "method": "kerberos", "status": "success"}
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(180, 360),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "lateral_movement", "sequence": 3},
            "action": "allowed",
        },
    )
    evt3["process"] = {
        "name": "wmic.exe",
        "command_line": "wmic /node:fileserver01 process call create cmd.exe /c whoami",
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events
