import sys
from pathlib import Path
import unittest
from datetime import datetime

# Add project root to path for module imports
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.attack_chains.builder import build_base_event  # noqa: E402
from scripts.attack_chains.generator import (  # noqa: E402
    _clamp_event_time,
    _clamp_ratio,
    _retime_chain_events,
)
from scripts.attack_chains.seasonal_noise import SeasonalNoiseModel  # noqa: E402


class GeneratorUnitTests(unittest.TestCase):
    def test_clamp_ratio_bounds(self):
        self.assertEqual(_clamp_ratio(-0.5), 0.0)
        self.assertEqual(_clamp_ratio(0.5), 0.5)
        self.assertEqual(_clamp_ratio(1.5), 0.95)

    def test_clamp_event_time(self):
        start_ts = 100
        end_ts = 200
        evt = {"@timestamp": "1970-01-01T00:10:00"}
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

    def test_platform_enrichment_sysmon_vs_auditd(self):
        win_ctx = {
            "source_ips": [],
            "dest_ips": [],
            "signatures": [],
            "categories_weighted": [("psexec_lateral", 1.0)],
            "severity_weighted": [("3", 1.0)],
            "assets": [{"Hostname": "WIN-01", "IP_Address": "10.0.0.5", "OS": "Windows 11"}],
            "ip_to_asset": {},
            "ad_users": [{"Username": "alice"}],
        }
        win_evt = build_base_event(1700000000, win_ctx)
        self.assertEqual(win_evt["host"]["os"]["platform"], "windows")
        self.assertIn("winlog", win_evt)
        self.assertEqual(win_evt["event"]["provider"], "Microsoft-Windows-Sysmon")

        lin_ctx = {
            "source_ips": [],
            "dest_ips": [],
            "signatures": [],
            "categories_weighted": [("ssh_agent_abuse", 1.0)],
            "severity_weighted": [("2", 1.0)],
            "assets": [{"Hostname": "SRV-01", "IP_Address": "10.0.0.9", "OS": "RHEL 8.5"}],
            "ip_to_asset": {},
            "ad_users": [{"Username": "bob"}],
        }
        lin_evt = build_base_event(1700000000, lin_ctx)
        self.assertEqual(lin_evt["host"]["os"]["platform"], "linux")
        self.assertIn("auditd", lin_evt)
        self.assertEqual(lin_evt["event"]["provider"], "auditd")
        self.assertNotIn("winlog", lin_evt)

    def test_retime_chain_events_monotonic(self):
        base_ts = 1_700_000_000
        events = [
            {"@timestamp": "", "attack": {"sequence": 2, "stage": "exfiltration"}},
            {"@timestamp": "", "attack": {"sequence": 1, "stage": "initial_access"}},
            {"@timestamp": "", "attack": {"sequence": 3, "stage": "impact"}},
        ]
        retimed = _retime_chain_events(events, base_ts)
        seq_order = sorted(retimed, key=lambda e: e["attack"]["sequence"])
        times = [int(datetime.fromisoformat(evt["@timestamp"]).timestamp()) for evt in seq_order]
        self.assertTrue(all(t2 >= t1 for t1, t2 in zip(times, times[1:])))


class SeasonalNoiseTests(unittest.TestCase):
    def test_seasonal_timestamp_stays_in_window(self):
        model = SeasonalNoiseModel(enabled=True, tz_offset_hours=0)
        start_ts = 0
        end_ts = 3600 * 24
        ts = model.pick_timestamp(start_ts, end_ts)
        self.assertGreaterEqual(ts, start_ts)
        self.assertLessEqual(ts, end_ts)

    def test_seasonal_scenario_selection_valid(self):
        model = SeasonalNoiseModel(enabled=True, tz_offset_hours=0)
        scenario = model.pick_scenario(0)
        self.assertIn(
            scenario,
            ["dns_update", "vuln_scanner", "normal_login", "approved_backup", "red_team_scan"],
        )


if __name__ == "__main__":
    unittest.main()
