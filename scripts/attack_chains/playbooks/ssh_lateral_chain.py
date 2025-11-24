import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def ssh_lateral_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Linux lateral movement chain using SSH and data staging."""
    shared = _shared_context(ctx)
    events = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "malcore",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 1},
            "dest_port": 22,
            "direction": "inbound",
            "action": "blocked",
        },
    )
    evt1["logon"] = {"failure_reason": random.choice(["bad_password", "expired_password"]), "type": "network"}
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(10, 60),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "lateral_movement", "sequence": 2},
            "dest_port": 22,
            "direction": "inbound",
            "action": "allowed",
        },
    )
    evt2["process"] = {
        "pid": random.randint(2000, 6000),
        "name": "ssh",
        "command_line": f"ssh -o StrictHostKeyChecking=no user@{shared['dst_ip']}",
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(90, 240),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "collection", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["process"] = {"name": "tar", "command_line": "tar -czf /tmp/ssl_backup.tgz /etc/ssl"}
    evt3["file"] = {
        "path": "/tmp/ssl_backup.tgz",
        "extension": "tgz",
        "size": random.randint(800000, 2500000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events
