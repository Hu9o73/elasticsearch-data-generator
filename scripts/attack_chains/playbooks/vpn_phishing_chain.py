import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_domain, _rand_hash, _shared_context


def vpn_phishing_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Phishing-led VPN compromise followed by data theft over HTTPS."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

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
            "action": "allowed",
        },
    )
    evt1["logon"] = {
        "type": "vpn",
        "status": "success",
        "method": "push",
        "geo": random.choice(["CN", "RU", "RO", "BR", "NG"]),
    }
    evt1["network"]["direction"] = "inbound"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(5, 60),
        ctx,
        overrides={
            **shared,
            "category": "malicious_powershell_detect",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "execution", "sequence": 2},
            "action": "logged",
        },
    )
    encoded = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", k=70))
    evt2["process"] = {
        "name": "powershell.exe",
        "command_line": f"powershell.exe -nop -w hidden -enc {encoded}",
        "parent": {"name": "explorer.exe", "command_line": "explorer.exe"},
    }
    evt2["dns"] = {"question": {"name": f"cdn.{_rand_domain()}", "type": "A"}}
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(90, 240),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 3},
            "action": "blocked",
        },
    )
    evt3["http"] = {"method": "POST", "response": {"status_code": random.choice([200, 202, 403])}}
    evt3["url"] = {"full": f"https://{_rand_domain()}/upload.php"}
    evt3["file"] = {
        "path": "C:\\Users\\Public\\vpn_creds.csv",
        "extension": "csv",
        "size": random.randint(10000, 60000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["network"]["direction"] = "outbound"
    _append_and_maybe_stop(events, evt3)

    return events
