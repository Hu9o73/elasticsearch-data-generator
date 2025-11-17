import random
import string
from typing import Any, Dict, List

from .builder import build_base_event


def _rand_domain() -> str:
    name = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(8, 14)))
    tld = random.choice(["com", "net", "biz", "co"])
    return f"{name}.{tld}"


def _rand_hash() -> str:
    letters = string.hexdigits.lower()
    return "".join(random.choices(letters, k=64))


def _shared_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Pick user/asset/ip once so multiple events feel linked."""
    user = random.choice(ctx.get("ad_users", [{"Username": "unknown"}]))
    dst_ip = random.choice(ctx.get("dest_ips", ["10.0.1.20"]))
    asset = ctx.get("ip_to_asset", {}).get(dst_ip) or random.choice(ctx.get("assets", [{}]))
    src_ip = random.choice(ctx.get("source_ips", ["198.51.100.42"]))
    return {"user": user, "dst_ip": dst_ip, "asset": asset, "src_ip": src_ip}


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
            "outcome": "failure",
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
    events.append(evt1)

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
            "outcome": "success",
        },
    )
    evt2["process"] = {
        "pid": random.randint(5000, 11000),
        "name": "whoami.exe",
        "command_line": "whoami /all",
    }
    events.append(evt2)

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
            "outcome": random.choice(["failure", "success"]),
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
    events.append(evt3)

    return events


def ssh_lateral_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Linux lateral movement chain using SSH and data staging."""
    shared = _shared_context(ctx)
    events = []

    # Step 1: brute force / credential stuffing
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
            "outcome": "failure",
        },
    )
    evt1["logon"] = {"failure_reason": random.choice(["bad_password", "expired_password"]), "type": "network"}
    events.append(evt1)

    # Step 2: successful SSH and recon
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
            "outcome": "success",
        },
    )
    evt2["process"] = {
        "pid": random.randint(2000, 6000),
        "name": "ssh",
        "command_line": f"ssh -o StrictHostKeyChecking=no user@{shared['dst_ip']}",
    }
    events.append(evt2)

    # Step 3: staging data for exfil
    evt3 = build_base_event(
        start_ts + random.randint(90, 240),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "collection", "sequence": 3},
            "action": "logged",
            "outcome": random.choice(["success", "failure"]),
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
    events.append(evt3)

    return events


PLAYBOOKS = [powershell_dropper_chain, ssh_lateral_chain]
