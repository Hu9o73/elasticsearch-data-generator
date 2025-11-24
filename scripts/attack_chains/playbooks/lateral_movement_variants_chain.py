import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def lateral_movement_variants_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Mixed lateral movement: WMI, PsExec, RDP file move, SSH agent hop, Kerberoasting."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "wmi_lateral",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "lateral_movement", "sequence": 1},
            "action": "allowed",
            "direction": "internal",
        },
    )
    evt1["process"] = {"name": "wmic.exe", "command_line": f"wmic /node:{shared['dst_ip']} process call create calc.exe"}
    evt1["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(180, 420),
        ctx,
        overrides={
            **shared,
            "category": "psexec_lateral",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "execution", "sequence": 2},
            "action": "logged",
            "direction": "internal",
        },
    )
    evt2["process"] = {"name": "psexec.exe", "command_line": f"psexec.exe \\\\{shared['dst_ip']} -c svc_host.exe"}
    evt2["file"] = {
        "path": "C:\\Windows\\Temp\\svc_host.exe",
        "extension": "exe",
        "size": random.randint(150000, 400000),
        "hash": {"sha256": _rand_hash()},
    }
    evt2["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(600, 1200),
        ctx,
        overrides={
            **shared,
            "category": "rdp_lateral",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "lateral_movement", "sequence": 3},
            "action": random.choice(["allowed", "blocked"]),
        },
    )
    evt3["process"] = {"name": "mstsc.exe", "command_line": "mstsc.exe /v:print01.fusionai.local /f"}
    evt3["file"] = {"path": "C:\\Users\\Public\\tools.zip", "extension": "zip", "size": random.randint(2000000, 6000000)}
    evt3["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1500, 2400),
        ctx,
        overrides={
            **shared,
            "category": "ssh_agent_abuse",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 4},
            "action": "logged",
        },
    )
    evt4["process"] = {"name": "ssh", "command_line": "ssh -A jump-host 'scp /tmp/tools.zip 10.0.2.8:/tmp/tools.zip'"}
    evt4["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt4):
        return events

    evt5 = build_base_event(
        start_ts + random.randint(2200, 3600),
        ctx,
        overrides={
            **shared,
            "category": "kerberoast_detect",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 5},
            "action": "blocked",
        },
    )
    evt5["process"] = {"name": "rubeus.exe", "command_line": "Rubeus.exe kerberoast /nowrap /domain:fusionai.local"}
    evt5["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt5)

    return events
