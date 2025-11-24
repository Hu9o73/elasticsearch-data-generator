import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def defense_evasion_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """EDR tamper, AMSI bypass, Sysmon removal, timestomp, signed driver abuse."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "edr_tamper",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 1},
            "action": random.choice(["blocked", "logged"]),
        },
    )
    evt1["process"] = {"name": "sc.exe", "command_line": "sc stop CrowdStrikeFalconSensor && sc delete CrowdStrikeFalconSensor"}
    evt1["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(120, 360),
        ctx,
        overrides={
            **shared,
            "category": "amsi_bypass",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "powershell.exe",
        "command_line": "powershell -nop -enc SQBtAEEAUwBJACAAPQAgAEcAZQB0AC0AVwBpAG4AMwAyAFMALgBIAG8AbgBhAHIAdwBlAC4AQQBtAHMAaQAK",
    }
    evt2["file"] = {"path": "C:\\Windows\\Temp\\amsi_patch.bin", "extension": "bin", "hash": {"sha256": _rand_hash()}}
    evt2["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(600, 1200),
        ctx,
        overrides={
            **shared,
            "category": "sysmon_disable",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["process"] = {"name": "wevtutil.exe", "command_line": "wevtutil sl Microsoft-Windows-Sysmon/Operational /e:false"}
    evt3["registry"] = {"path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv", "value": "Start=4"}
    evt3["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1500, 2400),
        ctx,
        overrides={
            **shared,
            "category": "timestomp_activity",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 4},
            "action": "logged",
        },
    )
    evt4["file"] = {"path": "C:\\Users\\Public\\report.docx", "extension": "docx", "mtime": "2001-01-01T00:00:00Z"}
    evt4["process"] = {"name": "powershell.exe", "command_line": "Set-ItemProperty -Path report.docx -Name LastWriteTime -Value '01/01/2001'"}
    evt4["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt4):
        return events

    evt5 = build_base_event(
        start_ts + random.randint(2200, 3600),
        ctx,
        overrides={
            **shared,
            "category": "signed_driver_abuse",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "persistence", "sequence": 5},
            "action": random.choice(["blocked", "allowed"]),
        },
    )
    evt5["file"] = {
        "path": "C:\\Windows\\Temp\\iqvw64e.sys",
        "extension": "sys",
        "size": random.randint(200000, 700000),
        "hash": {"sha256": _rand_hash()},
    }
    evt5["process"] = {"name": "pnputil.exe", "command_line": "pnputil /add-driver iqvw64e.inf /install"}
    evt5["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt5)

    return events
