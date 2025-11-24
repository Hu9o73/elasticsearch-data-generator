import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def insider_misuse_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Insider abuse after hours with database dumps and removable media."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "insider_data_theft",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "collection", "sequence": 1},
            "action": "logged",
        },
    )
    evt1["process"] = {"name": "psql", "command_line": 'psql -c "COPY hr.employees TO \'/tmp/hr_dump.csv\' CSV"'}
    evt1["file"] = {
        "path": "/tmp/hr_dump.csv",
        "extension": "csv",
        "size": random.randint(900000, 2500000),
        "hash": {"sha256": _rand_hash()},
    }
    evt1["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(300, 900),
        ctx,
        overrides={
            **shared,
            "category": "insider_data_theft",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 2},
            "action": random.choice(["allowed", "logged"]),
        },
    )
    evt2["url"] = {"full": f"https://{random.choice(['dropbox.com', 'mega.nz'])}/upload"}
    evt2["http"] = {"method": "POST", "response": {"status_code": random.choice([200, 201, 429])}}
    evt2["file"] = {
        "path": "/tmp/hr_dump.csv",
        "extension": "csv",
        "size": evt1["file"]["size"],
        "hash": evt1["file"]["hash"],
    }
    evt2["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(1200, 2100),
        ctx,
        overrides={
            **shared,
            "category": "usb_mass_copy",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["file"] = {
        "path": "E:\\HR\\hr_dump.csv",
        "extension": "csv",
        "size": evt1["file"]["size"],
        "hash": evt1["file"]["hash"],
        "device": "USB",
    }
    evt3["process"] = {"name": "explorer.exe", "command_line": "copy /Y C:\\Users\\Public\\hr_dump.csv E:\\HR\\"}
    evt3["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1800, 3200),
        ctx,
        overrides={
            **shared,
            "category": "sudo_misuse",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "privilege_escalation", "sequence": 4},
            "action": random.choice(["blocked", "allowed"]),
        },
    )
    evt4["process"] = {"name": "sudo", "command_line": "sudo su -", "exit_code": random.choice([1, 1, 0])}
    evt4["logon"] = {"type": "tty", "status": "failure" if evt4["process"]["exit_code"] else "success"}
    evt4["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt4):
        return events

    evt5 = build_base_event(
        start_ts + random.randint(2400, 4200),
        ctx,
        overrides={
            **shared,
            "category": "sudo_misuse",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "execution", "sequence": 5},
            "action": "logged",
        },
    )
    evt5["process"] = {"name": "bash", "command_line": "bash -c 'tar -czf /tmp/projects.tgz /srv/git'"}
    evt5["file"] = {
        "path": "/tmp/projects.tgz",
        "extension": "tgz",
        "size": random.randint(5_000_000, 15_000_000),
        "hash": {"sha256": _rand_hash()},
    }
    evt5["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt5)

    return events
