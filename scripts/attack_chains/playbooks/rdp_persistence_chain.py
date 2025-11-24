import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _shared_context


def rdp_persistence_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Credential reuse leading to RDP access and persistence via scheduled task."""
    shared = _shared_context(ctx)
    events = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "malcore",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 1},
            "dest_port": 3389,
            "direction": "inbound",
            "action": "allowed",
        },
    )
    evt1["logon"] = {"type": "rdp", "method": "network"}
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(15, 60),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "persistence", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "schtasks.exe",
        "command_line": 'schtasks /Create /SC MINUTE /MO 30 /TN "OneDrive Updater" /TR "C:\\Windows\\Temp\\svc.exe"',
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(90, 300),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "lateral_movement", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["process"] = {
        "name": "mstsc.exe",
        "command_line": "mstsc.exe /v:fileserver01.fusionai.local",
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events
