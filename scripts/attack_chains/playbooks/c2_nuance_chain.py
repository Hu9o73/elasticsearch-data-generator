import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_domain, _shared_context


def c2_nuance_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Command and control hiding in domain fronting, DoH, and cloud storage APIs."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "c2_domain_fronting",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "command_and_control", "sequence": 1},
            "action": "logged",
        },
    )
    evt1["network"]["direction"] = "outbound"
    evt1["url"] = {"full": "https://cdn.microsoft.com/update"}
    evt1["http"] = {"request": {"headers": {"Host": "fronting.azureedge.net"}}, "response": {"status_code": 200}}
    evt1["tls"] = {"sni": "fronting.azureedge.net"}
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(180, 420),
        ctx,
        overrides={
            **shared,
            "category": "doh_beacon",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "command_and_control", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["http"] = {"method": "GET", "response": {"status_code": 200}}
    evt2["url"] = {"full": "https://cloudflare-dns.com/dns-query?dns=AAABAA"}
    evt2["dns"] = {"question": {"name": _rand_domain(), "type": "TXT"}}
    evt2["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(900, 1500),
        ctx,
        overrides={
            **shared,
            "category": "cloud_storage_c2",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "command_and_control", "sequence": 3},
            "action": random.choice(["logged", "blocked"]),
        },
    )
    evt3["http"] = {"method": "PUT", "response": {"status_code": random.choice([200, 403])}}
    evt3["url"] = {"full": f"https://graph.microsoft.com/v1.0/me/drive/root:/{random.randint(10,99)}.dat:/content"}
    evt3["user_agent"] = {"original": random.choice(["OneDriveSync/23.1", "GDriveSync/11.5"])}
    evt3["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1800, 2600),
        ctx,
        overrides={
            **shared,
            "category": "c2_jitter",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "command_and_control", "sequence": 4},
            "action": "logged",
        },
    )
    evt4["http"] = {"method": "POST", "response": {"status_code": 200}}
    evt4["url"] = {"full": f"https://{_rand_domain()}/beacon"}
    evt4["network"]["direction"] = "outbound"
    evt4["user_agent"] = {"original": random.choice(["Mozilla/5.0", "curl/7.88", "aws-cli/2.11"])}
    evt4["fusionai"] = {**evt4.get("fusionai", {}), "jitter_seconds": random.randint(30, 600)}
    _append_and_maybe_stop(events, evt4)

    return events
