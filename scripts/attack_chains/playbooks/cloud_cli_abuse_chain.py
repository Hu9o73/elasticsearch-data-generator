import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


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
