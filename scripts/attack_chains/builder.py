import random
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
    }
    return mitre_map.get(category, ("T1071", "Unknown"))


def _resolve_asset(dst_ip: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    if ctx.get("ip_to_asset") and dst_ip in ctx["ip_to_asset"]:
        return ctx["ip_to_asset"][dst_ip]
    return random.choice(ctx["assets"])


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

    src_ip = overrides.get("src_ip") or _choose_ip(ctx.get("source_ips", []), "198.51.100.10")
    dst_ip = overrides.get("dst_ip") or _choose_ip(ctx.get("dest_ips", []), "10.0.1.10")

    asset = overrides.get("asset") or _resolve_asset(dst_ip, ctx)
    user = overrides.get("user") or random.choice(ctx.get("ad_users", [{"Username": "unknown"}]))

    src_port = overrides.get("src_port") or (random.choice(ctx.get("real_src_ports", [])) if ctx.get("real_src_ports") else random.randint(49152, 65535))
    dest_port = overrides.get("dest_port") or (random.choice(ctx.get("real_dest_ports", [])) if ctx.get("real_dest_ports") else random.choice([80, 443, 445, 3389, 22]))
    protocol = overrides.get("protocol") or (random.choice(ctx.get("real_protocols", [])) if ctx.get("real_protocols") else "TCP")

    severity_text = _severity_text(severity)
    mitre_technique, mitre_tactic = _mitre_for_category(category)

    event = {
        "@timestamp": dt.isoformat(),
        "event": {
            "category": "security",
            "type": "alert",
            "kind": "alert",
            "severity": severity_text,
            "action": overrides.get("action") or random.choice(["allowed", "blocked", "logged"]),
            "outcome": overrides.get("outcome") or random.choice(["success", "failure", "unknown"]),
            "module": category,
            "dataset": "fusionai.alerts",
        },
        "source": {"ip": src_ip, "port": src_port, "bytes": random.randint(100, 50000)},
        "destination": {"ip": dst_ip, "port": dest_port, "bytes": random.randint(500, 100000)},
        "network": {
            "protocol": protocol.lower() if protocol else "tcp",
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
            "ip": [dst_ip],
            "mac": [asset.get("MAC_Address", "")] if asset.get("MAC_Address") else [],
            "os": {
                "name": asset.get("OS", "Unknown"),
                "platform": "linux" if "Linux" in asset.get("OS", "") or "Ubuntu" in asset.get("OS", "") else "windows",
            },
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

    return event
