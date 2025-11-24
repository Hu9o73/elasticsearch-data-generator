import random
import string
from typing import Any, Dict, List


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
    ("allowed", "failure"): 0.6,
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
