import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


def weighted_choice(choices_weights: List[Tuple[Any, float]], default: Any) -> Any:
    """Select an element according to weights; use default if distribution is empty."""
    if not choices_weights:
        return default
    choices, weights = zip(*choices_weights)
    total = sum(weights)
    r = random.uniform(0, total)
    upto = 0
    for choice, weight in zip(choices, weights):
        if upto + weight >= r:
            return choice
        upto += weight
    return choices[-1]


def _choose_ip(ip_list: List[str], fallback: str) -> str:
    return random.choice(ip_list) if ip_list else fallback


def _severity_text(severity: str) -> str:
    mapping = {"1": "low", "2": "medium", "3": "high", "4": "critical"}
    return mapping.get(str(severity), "medium")


def _mitre_for_category(category: str) -> Tuple[str, str]:
    mitre_map = {
        "malcore": ("T1059", "Execution"),
        "sigflow_alert": ("T1071", "Command and Control"),
        "dga_detect": ("T1568", "Command and Control"),
        "malicious_powershell_detect": ("T1059.001", "Execution"),
        "shellcode_detect": ("T1055", "Defense Evasion"),
        "retrohunt": ("T1087", "Discovery"),
        "cloud_iam_anomaly": ("T1078", "Credential Access"),
        "cloud_discovery": ("T1580", "Discovery"),
        "cloud_privilege_escalation": ("T1098.003", "Persistence"),
        "cloud_data_exfil": ("T1567.002", "Exfiltration"),
        "cloud_resource_hijack": ("T1496", "Impact"),
        "oauth_consent_abuse": ("T1098.003", "Persistence"),
        "saas_account_takeover": ("T1078.004", "Credential Access"),
        "mailbox_rule_abuse": ("T1114.003", "Collection"),
        "cloud_storage_mass_download": ("T1537", "Exfiltration"),
        "insider_data_theft": ("T1074.001", "Collection"),
        "usb_mass_copy": ("T1052", "Exfiltration"),
        "sudo_misuse": ("T1548", "Privilege Escalation"),
        "wmi_lateral": ("T1047", "Lateral Movement"),
        "psexec_lateral": ("T1021.002", "Lateral Movement"),
        "rdp_lateral": ("T1021.001", "Lateral Movement"),
        "ssh_agent_abuse": ("T1552.004", "Credential Access"),
        "kerberoast_detect": ("T1558.003", "Credential Access"),
        "phishing_macro": ("T1204.002", "Initial Access"),
        "iso_lnk_delivery": ("T1204.002", "Initial Access"),
        "html_smuggling": ("T1027.006", "Initial Access"),
        "lolbin_download_exec": ("T1218", "Execution"),
        "edr_tamper": ("T1562.001", "Defense Evasion"),
        "amsi_bypass": ("T1059.001", "Defense Evasion"),
        "sysmon_disable": ("T1562.002", "Defense Evasion"),
        "timestomp_activity": ("T1070.006", "Defense Evasion"),
        "signed_driver_abuse": ("T1553.006", "Defense Evasion"),
        "c2_domain_fronting": ("T1090.004", "Command and Control"),
        "doh_beacon": ("T1071.004", "Command and Control"),
        "cloud_storage_c2": ("T1102.002", "Command and Control"),
        "c2_jitter": ("T1071", "Command and Control"),
        "data_staging_archive": ("T1074.001", "Collection"),
        "pastebin_chunk_exfil": ("T1567.002", "Exfiltration"),
        "dns_tunnel": ("T1071.004", "Exfiltration"),
        "smb_rogue_transfer": ("T1021.002", "Exfiltration"),
        "curl_binary_exfil": ("T1048.003", "Exfiltration"),
        "ransomware_extended": ("T1486", "Impact"),
        "gpo_abuse": ("T1484.001", "Defense Evasion"),
        "backup_wipe": ("T1490", "Impact"),
        "ci_pipeline_abuse": ("T1195", "Initial Access"),
        "dependency_confusion": ("T1195.002", "Initial Access"),
        "github_pat_misuse": ("T1552.001", "Credential Access"),
        "secret_scan_block": ("T1552", "Credential Access"),
    }
    return mitre_map.get(category, ("T1071", "Unknown"))


def _resolve_asset(dst_ip: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    if ctx.get("ip_to_asset") and dst_ip in ctx["ip_to_asset"]:
        return ctx["ip_to_asset"][dst_ip]
    # Fall back to any known asset to keep host metadata populated
    return random.choice(ctx["assets"]) if ctx.get("assets") else {}


def _derive_platform(asset: Dict[str, Any]) -> str:
    os_name = (asset.get("OS") or asset.get("os") or "").lower()
    linux_markers = ["linux", "ubuntu", "debian", "centos", "rhel", "red hat", "fedora", "suse", "oracle", "amazon linux", "rocky", "almalinux"]
    if any(k in os_name for k in linux_markers):
        return "linux"
    if "win" in os_name or "microsoft" in os_name:
        return "windows"
    if any(k in os_name for k in ["mac", "darwin"]):
        return "macos"
    return "linux"


def _rand_domain_label(length: int = 10) -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=length))


def _normalize_protocol(proto: Any) -> Tuple[str, List[str]]:
    """Return canonical protocol plus a list for multi-valued sources."""
    if proto is None:
        return "tcp", ["tcp"]
    if isinstance(proto, str):
        raw = proto.strip().lower()
        if raw.startswith("[") and raw.endswith("]"):
            try:
                parsed = [p.strip().strip("\"'") for p in raw.strip("[]").split(",") if p.strip()]
                if parsed:
                    return parsed[0], parsed
            except Exception:
                pass
        return raw, [raw]
    if isinstance(proto, (list, tuple)) and proto:
        canon = str(proto[0]).lower()
        return canon, [str(p).lower() for p in proto]
    raw = str(proto).lower()
    return raw, [raw]


def _sysmon_event_kind(category: str) -> str:
    cat = category.lower()
    if any(k in cat for k in ["credential", "kerberoast", "golden", "lsass", "ssh_agent", "secret", "github_pat"]):
        return "process_access"  # Sysmon 10
    if any(k in cat for k in ["tamper", "sysmon_disable", "signed_driver", "driver", "gpo", "edr"]):
        return "process_tamper"  # Sysmon 25
    if "dns" in cat or "dga" in cat:
        return "dns"
    if any(k in cat for k in ["dll", "driver", "signed_driver"]):
        return "image_load"  # Sysmon 7
    if any(k in cat for k in ["file", "backup", "staging", "exfil", "ransom", "wiper", "encrypt"]):
        return "file"
    if any(k in cat for k in ["registry", "gpo", "amsi", "sysmon", "timestomp", "persistence"]):
        return "registry"
    if any(k in cat for k in ["lateral", "c2", "beacon", "ssh", "rdp", "psexec", "wmi", "curl", "http", "tunnel", "fronting"]):
        return "network"
    return "process"


def _apply_sysmon_enrichment(event: Dict[str, Any], category: str) -> None:
    """Attach Sysmon-like metadata so Windows events look like real EDR telemetry."""
    kind = _sysmon_event_kind(category)
    event_code = {
        "dns": 22,
        "file": 11,
        "registry": 13,
        "network": 3,
        "image_load": 7,
        "process_access": 10,
        "process_tamper": 25,
        "process": 1,
    }.get(kind, 1)

    process = event.get("process", {})
    attack = event.get("attack", {})
    attack_id = attack.get("id", "")
    seq = attack.get("sequence", 0)
    rng = random.Random(f"{attack_id}-{seq}") if attack_id else random
    exe = process.get("executable") or process.get("name") or "C:\\Windows\\System32\\svchost.exe"
    cmdline = process.get("command_line") or exe
    domain = event.get("user", {}).get("domain", "")
    username = event.get("user", {}).get("name", "unknown")
    domain_user = f"{domain}\\{username}" if domain else username
    ts = event.get("@timestamp", datetime.utcnow().isoformat())
    guid = "{" + "".join(rng.choices("0123456789abcdef", k=32)) + "}"
    parent_guid = "{" + "".join(rng.choices("0123456789abcdef", k=32)) + "}"
    pid = rng.randint(400, 20000)
    parent_pid = max(100, pid - rng.randint(50, 900))
    event.setdefault("process", {})
    event["process"].setdefault("pid", pid)
    event["process"].setdefault("parent", {"pid": parent_pid})

    if kind == "dns":
        dns_name = event.get("dns", {}).get("question", {}).get("name") or f"{_rand_domain_label(random.randint(6, 10))}.{random.choice(['com', 'net', 'org'])}"
        event_data = {
            "UtcTime": f"{ts}Z",
            "Image": exe,
            "QueryName": dns_name,
            "QueryStatus": "0",
            "QueryResults": event.get("destination", {}).get("ip", "0.0.0.0"),
            "User": domain_user,
        }
    elif kind == "image_load":
        target = event.get("file", {}).get("path") or f"C:\\Windows\\System32\\{_rand_domain_label(6)}.dll"
        hash_hex = "".join(rng.choices("0123456789abcdef", k=64))
        event_data = {
            "UtcTime": f"{ts}Z",
            "Image": exe,
            "ImageLoaded": target,
            "Hashes": f"SHA256={hash_hex}",
            "Signed": rng.choice(["true", "false"]),
            "SignatureStatus": rng.choice(["Valid", "Invalid", "Unavailable"]),
            "ProcessGuid": guid,
            "ProcessId": pid,
        }
    elif kind == "process_access":
        target_img = process.get("target_image") or "C:\\Windows\\System32\\lsass.exe"
        event_data = {
            "UtcTime": f"{ts}Z",
            "SourceImage": exe,
            "TargetImage": target_img,
            "GrantedAccess": hex(rng.randint(0x1000, 0x3010)),
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+0x9e300",
            "SourceProcessGUID": guid,
            "SourceProcessId": pid,
            "TargetProcessGUID": "{" + "".join(rng.choices("0123456789abcdef", k=32)) + "}",
            "TargetProcessId": rng.randint(400, 8000),
            "User": domain_user,
        }
    elif kind == "process_tamper":
        target_img = process.get("target_image") or exe
        event_data = {
            "UtcTime": f"{ts}Z",
            "Image": exe,
            "TargetImage": target_img,
            "TargetProcessId": rng.randint(300, 8000),
            "Status": "0x0",
            "CallTrace": "C:\\Windows\\System32\\ntdll.dll+0x2e4a0",
            "User": domain_user,
            "ProcessGuid": guid,
            "ProcessId": pid,
        }
    elif kind == "file":
        target = event.get("file", {}).get("path") or f"C:\\Users\\Public\\{_rand_domain_label(8)}.dat"
        event_data = {
            "UtcTime": f"{ts}Z",
            "Image": exe,
            "TargetFilename": target,
            "CreationUtcTime": f"{ts}Z",
            "User": domain_user,
            "ProcessGuid": guid,
            "ProcessId": pid,
        }
    elif kind == "registry":
        target_obj = event.get("registry", {}).get("path") or "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        event_data = {
            "UtcTime": f"{ts}Z",
            "Image": exe,
            "TargetObject": target_obj,
            "EventType": random.choice(["SetValue", "CreateKey"]),
            "Details": "DWORD (0x00000000)",
            "User": domain_user,
            "ProcessGuid": guid,
            "ProcessId": pid,
        }
    elif kind == "network":
        event_data = {
            "UtcTime": f"{ts}Z",
            "Image": exe,
            "User": domain_user,
            "Protocol": event.get("network", {}).get("protocol", "tcp").upper(),
            "SourceIp": event.get("source", {}).get("ip"),
            "SourcePort": event.get("source", {}).get("port"),
            "DestinationIp": event.get("destination", {}).get("ip"),
            "DestinationPort": event.get("destination", {}).get("port"),
            "Initiated": "true" if event.get("network", {}).get("direction") != "inbound" else "false",
            "ProcessGuid": guid,
            "ProcessId": pid,
        }
    else:  # process creation baseline
        parent_image = process.get("parent_executable") or "C:\\Windows\\System32\\services.exe"
        parent_cmd = process.get("parent_command_line") or parent_image
        event_data = {
            "UtcTime": f"{ts}Z",
            "Image": exe,
            "CommandLine": cmdline,
            "ParentImage": parent_image,
            "ParentCommandLine": parent_cmd,
            "ProcessGuid": guid,
            "ProcessId": pid,
            "ParentProcessGuid": parent_guid,
            "ParentProcessId": parent_pid,
            "User": domain_user,
        }

    event["event"]["code"] = str(event_code)
    event["event"]["provider"] = "Microsoft-Windows-Sysmon"
    event["winlog"] = {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider_name": "Microsoft-Windows-Sysmon",
        "computer_name": event.get("host", {}).get("hostname"),
        "event_id": event_code,
        "record_id": random.randint(10_000, 2_000_000),
        "opcode": "Info",
        "process": {"pid": pid, "thread_id": random.randint(1000, 5000)},
        "event_data": event_data,
    }


def _apply_linux_audit_enrichment(event: Dict[str, Any], category: str) -> None:
    """Attach auditd/syslog-like metadata for Linux assets."""
    # Pick a plausible process/exe for the category so alerts feel grounded.
    cat = category.lower()
    if any(k in cat for k in ["ssh", "lateral"]):
        exe = "/usr/sbin/sshd"
        audit_type = "USER_LOGIN"
    elif "dns" in cat:
        exe = "/usr/bin/dig"
        audit_type = "USER_CMD"
    elif any(k in cat for k in ["sudo", "privilege", "persistence"]):
        exe = "/usr/bin/sudo"
        audit_type = "CRED_ACQ"
    elif any(k in cat for k in ["file", "exfil", "ransom", "backup"]):
        exe = "/usr/bin/curl"
        audit_type = "SYSCALL"
    else:
        exe = "/usr/bin/python3"
        audit_type = "USER_CMD"

    pid = random.randint(300, 20000)
    tty = f"pts/{random.randint(0, 6)}"
    username = event.get("user", {}).get("name", "unknown")
    outcome = event.get("event", {}).get("outcome")
    success = "yes" if outcome == "success" else "no"
    cmd = event.get("process", {}).get("command_line") or exe

    event["event"]["code"] = audit_type
    event["event"]["provider"] = "auditd"
    event["auditd"] = {
        "type": audit_type,
        "pid": pid,
        "uid": username,
        "auid": username,
        "tty": tty,
        "exe": exe,
        "msg": f"cwd=\"/home/{username}\" cmd=\"{cmd}\"",
        "success": success,
        "addr": event.get("source", {}).get("ip"),
    }
    event["log"] = {
        "level": "info" if success == "yes" else "warning",
        "file": {"path": "/var/log/audit/audit.log"},
        "syslog": {"facility": "auth", "severity": "notice"},
    }


def build_base_event(
    timestamp: int,
    ctx: Dict[str, Any],
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a single ECS-like base event with optional overrides for correlation."""
    overrides = overrides or {}
    dt = datetime.fromtimestamp(timestamp)

    category = overrides.get("category") or weighted_choice(ctx.get("categories_weighted", []), "malicious_powershell_detect")
    severity = overrides.get("severity") or weighted_choice(ctx.get("severity_weighted", []), "3")
    signature = overrides.get("signature") or (random.choice(ctx.get("signatures", [])) if ctx.get("signatures") else f"default_signature_{category}")

    action = overrides.get("action") or random.choice(["allowed", "blocked", "logged"])
    if overrides.get("outcome"):
        outcome = overrides["outcome"]
    elif action == "blocked":
        outcome = "failure"
    elif action == "allowed":
        outcome = "success"
    else:
        outcome = random.choice(["success", "unknown", "failure"])

    src_ip = overrides.get("src_ip") or _choose_ip(ctx.get("source_ips", []), "198.51.100.10")
    override_dst_ip = overrides.get("dst_ip")
    dst_ip = override_dst_ip or _choose_ip(ctx.get("dest_ips", []), "10.0.1.10")

    asset = overrides.get("asset") or _resolve_asset(dst_ip, ctx)
    platform = _derive_platform(asset)
    # If we picked an unmapped asset and the caller did not force a dst_ip, align destination with the asset IP
    if not override_dst_ip and not overrides.get("asset") and asset.get("IP_Address"):
        dst_ip = asset["IP_Address"]
    user = overrides.get("user") or random.choice(ctx.get("ad_users", [{"Username": "unknown"}]))

    src_port = overrides.get("src_port") or (random.choice(ctx.get("real_src_ports", [])) if ctx.get("real_src_ports") else random.randint(49152, 65535))
    dest_port = overrides.get("dest_port") or (random.choice(ctx.get("real_dest_ports", [])) if ctx.get("real_dest_ports") else random.choice([80, 443, 445, 3389, 22]))
    raw_proto = overrides.get("protocol") or (random.choice(ctx.get("real_protocols", [])) if ctx.get("real_protocols") else "tcp")
    protocol, protocol_list = _normalize_protocol(raw_proto)

    severity_text = _severity_text(severity)
    mitre_technique, mitre_tactic = _mitre_for_category(category)

    event = {
        "@timestamp": dt.isoformat(),
        "event": {
            "category": "security",
            "type": "alert",
            "kind": "alert",
            "severity": severity_text,
            "action": action,
            "outcome": outcome,
            "module": category,
            "dataset": "fusionai.alerts",
        },
        "source": {"ip": src_ip, "port": src_port, "bytes": random.randint(100, 50000)},
        "destination": {"ip": dst_ip, "port": dest_port, "bytes": random.randint(500, 100000)},
        "network": {
            "protocol": protocol,
            "protocols": protocol_list,
            "bytes": random.randint(600, 150000),
            "direction": overrides.get("direction") or random.choice(["inbound", "outbound", "internal"]),
        },
        "user": {
            "name": user.get("Username", "unknown"),
            "domain": overrides.get("user_domain", "fusionai.local"),
            "email": user.get("Email", ""),
            "department": user.get("Department", "Unknown"),
            "full_name": user.get("Display_Name", ""),
        },
        "host": {
            "name": asset.get("Hostname", "unknown"),
            "hostname": asset.get("Hostname", "unknown"),
            "type": asset.get("Asset_Type", "Unknown"),
            "ip": [asset.get("IP_Address", dst_ip)],
            "mac": [asset.get("MAC_Address", "")] if asset.get("MAC_Address") else [],
            "os": {"name": asset.get("OS", "Unknown"), "platform": platform},
            "risk": {"static_level": asset.get("Criticality", "Medium").lower()},
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": {"id": [mitre_technique], "name": [category]},
            "tactic": {"name": [mitre_tactic]},
        },
        "rule": {"name": signature, "category": category, "id": str(random.randint(1000, 9999))},
        "fusionai": {
            "signature": signature,
            "category": category,
            "severity": severity,
            "asset_owner": asset.get("Owner", ""),
            "asset_location": asset.get("Location", ""),
            "asset_department": asset.get("Department", ""),
        },
        "tags": [
            category,
            severity_text,
            "fusionai",
            asset.get("Location", "unknown").lower().replace(" ", "_"),
        ],
        "labels": {"env": "production", "source": "fusionai_generator", "data_source": "real_fusion_ai"},
    }

    # Optional correlation metadata
    if overrides.get("attack"):
        event["attack"] = overrides["attack"]

    if platform == "windows":
        _apply_sysmon_enrichment(event, category)
    elif platform == "linux":
        _apply_linux_audit_enrichment(event, category)

    return event
