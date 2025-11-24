import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_domain, _rand_hash, _shared_context


def powershell_dropper_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Windows initial access chain: email -> PowerShell -> dropped binary -> outbound HTTP."""
    shared = _shared_context(ctx)
    events = []

    # Step 1: initial access via Outlook spawning PowerShell
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
    encoded = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", k=80))
    evt1["process"] = {
        "pid": random.randint(4000, 9000),
        "name": "powershell.exe",
        "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": f"powershell.exe -nop -w hidden -enc {encoded}",
        "parent": {
            "pid": random.randint(3000, 6500),
            "name": "outlook.exe",
            "command_line": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE /embedding",
        },
    }
    evt1["dns"] = {"question": {"name": _rand_domain(), "type": "A"}}
    evt1["http"] = {"method": "GET", "response": {"status_code": random.choice([200, 404])}}
    evt1["url"] = {"full": f"https://cdn.{_rand_domain()}/payload.bin"}
    evt1["file"] = {
        "path": "C:\\Windows\\Temp\\svch0st.exe",
        "extension": "exe",
        "size": random.randint(40000, 80000),
        "hash": {"sha256": _rand_hash()},
    }
    evt1["registry"] = {
        "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdater",
        "data.strings": ["C:\\Windows\\Temp\\svch0st.exe -m update"],
    }
    if _append_and_maybe_stop(events, evt1):
        return events

    # Step 2: recon after dropper landing
    evt2 = build_base_event(
        start_ts + random.randint(5, 45),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "recon", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "pid": random.randint(5000, 11000),
        "name": "whoami.exe",
        "command_line": "whoami /all",
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    # Step 3: exfil preparation via HTTPS PUT
    evt3 = build_base_event(
        start_ts + random.randint(60, 180),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 3},
            "action": "blocked",
        },
    )
    evt3["file"] = {
        "path": "C:\\Users\\Public\\report.zip",
        "extension": "zip",
        "size": random.randint(1500000, 5000000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["http"] = {"method": "PUT", "response": {"status_code": random.choice([200, 403, 500])}}
    evt3["url"] = {"full": f"https://{_rand_domain()}/upload"}
    evt3["network"]["direction"] = "outbound"
    _append_and_maybe_stop(events, evt3)

    return events
