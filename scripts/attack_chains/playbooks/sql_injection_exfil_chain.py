import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_domain, _rand_hash, _shared_context


def sql_injection_exfil_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Web to DB compromise: SQLi probe -> dump -> HTTPS exfiltration."""
    shared = _shared_context(ctx)
    events = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "malcore",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 1},
            "dest_port": 443,
            "direction": "inbound",
            "action": "blocked",
        },
    )
    evt1["http"] = {"method": "POST", "response": {"status_code": random.choice([403, 500, 200])}}
    evt1["url"] = {"full": f"https://{_rand_domain()}/login.php?user=admin'--"}
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(30, 120),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "collection", "sequence": 2},
            "action": "allowed",
        },
    )
    evt2["process"] = {
        "name": "mysqldump",
        "command_line": "mysqldump -u webapp -p*** customers > /tmp/customer_dump.sql",
    }
    evt2["file"] = {
        "path": "/tmp/customer_dump.sql",
        "extension": "sql",
        "size": random.randint(5_000_000, 25_000_000),
        "hash": {"sha256": _rand_hash()},
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(150, 360),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 3},
            "action": "blocked",
        },
    )
    evt3["http"] = {"method": "POST", "response": {"status_code": random.choice([200, 403])}}
    evt3["url"] = {"full": f"https://cdn.{_rand_domain()}/upload"}
    evt3["file"] = {
        "path": "/tmp/customer_dump.sql.gz",
        "extension": "gz",
        "size": random.randint(2_000_000, 10_000_000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["network"]["direction"] = "outbound"
    _append_and_maybe_stop(events, evt3)

    return events
