import sys
from pathlib import Path
import unittest

# Add project root to path for module imports
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.attack_chains.builder import build_base_event  # noqa: E402
from scripts.attack_chains.generator import _clamp_event_time, _clamp_ratio  # noqa: E402


class GeneratorUnitTests(unittest.TestCase):
    def test_clamp_ratio_bounds(self):
        self.assertEqual(_clamp_ratio(-0.5), 0.0)
        self.assertEqual(_clamp_ratio(0.5), 0.5)
        self.assertEqual(_clamp_ratio(1.5), 0.95)

    def test_clamp_event_time(self):
        start_ts = 100
        end_ts = 200
        evt = {"@timestamp": "1970-01-01T00:03:00"}
        clamped = _clamp_event_time(evt, start_ts, end_ts)
        self.assertEqual(clamped["@timestamp"], "1970-01-01T00:03:20")

        inside_evt = {"@timestamp": "1970-01-01T00:02:30"}
        self.assertEqual(_clamp_event_time(inside_evt, start_ts, end_ts), inside_evt)

    def test_host_destination_alignment_with_fallback_asset(self):
        ctx = {
            "source_ips": [],
            "dest_ips": [],
            "signatures": [],
            "categories_weighted": [("test", 1.0)],
            "severity_weighted": [("2", 1.0)],
            "assets": [{"Hostname": "WKS-001", "IP_Address": "10.0.2.5"}],
            "ip_to_asset": {},
            "ad_users": [{"Username": "alice"}],
        }
        evt = build_base_event(1700000000, ctx)
        self.assertEqual(evt["destination"]["ip"], "10.0.2.5")
        self.assertEqual(evt["host"]["ip"], ["10.0.2.5"])

    def test_destination_override_respected(self):
        ctx = {
            "source_ips": [],
            "dest_ips": [],
            "signatures": [],
            "categories_weighted": [("test", 1.0)],
            "severity_weighted": [("2", 1.0)],
            "assets": [{"Hostname": "WKS-002", "IP_Address": "10.0.4.9"}],
            "ip_to_asset": {},
            "ad_users": [{"Username": "bob"}],
        }
        evt = build_base_event(1700000000, ctx, overrides={"dst_ip": "192.0.2.10"})
        self.assertEqual(evt["destination"]["ip"], "192.0.2.10")
        # Host still reflects the asset for the provided destination
        self.assertEqual(evt["host"]["ip"], ["10.0.4.9"])


if __name__ == "__main__":
    unittest.main()
