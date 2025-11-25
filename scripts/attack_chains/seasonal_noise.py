import os
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List


def _enabled_from_env() -> bool:
    val = os.getenv("NOISE_SEASONALITY", "off").lower()
    return val in {"1", "true", "yes", "on"}


def _tz_offset_from_env() -> int:
    try:
        return int(os.getenv("NOISE_TZ_OFFSET", "0"))
    except ValueError:
        return 0


@dataclass
class SeasonalNoiseModel:
    """Lightweight seasonality model to cluster benign noise in realistic windows."""

    enabled: bool = None
    tz_offset_hours: int = None

    def __post_init__(self) -> None:
        if self.enabled is None:
            self.enabled = _enabled_from_env()
        if self.tz_offset_hours is None:
            self.tz_offset_hours = _tz_offset_from_env()
        self._tz_delta = timedelta(hours=self.tz_offset_hours)

    def _weight(self, dt: datetime) -> float:
        """Assign higher weights to business hours and maintenance windows."""
        hour = dt.hour
        weekday = dt.weekday()  # 0=Mon

        # Baseline weight
        weight = 1.0

        # Office hours (Mon-Fri 08-18) -> more benign logons/scans
        if weekday < 5 and 8 <= hour <= 18:
            weight = 3.0
        # Evening change windows (Sun 20-23 / Mon 00-02) -> backups/patches
        elif (weekday == 6 and hour >= 20) or (weekday == 0 and hour <= 2):
            weight = 2.5
        # Weekends otherwise slightly quieter
        elif weekday >= 5:
            weight = 0.6
        # Early mornings
        elif hour <= 6:
            weight = 0.7
        else:
            weight = 1.2

        return weight

    def pick_timestamp(self, start_ts: int, end_ts: int) -> int:
        """Draw a timestamp with seasonality weighting; fallback to uniform."""
        if not self.enabled or end_ts <= start_ts:
            return random.randint(start_ts, end_ts)

        start_dt = datetime.fromtimestamp(start_ts) + self._tz_delta
        hours_span = max(1, int((end_ts - start_ts) // 3600))

        weights: List[float] = []
        for i in range(hours_span):
            dt = start_dt + timedelta(hours=i)
            weights.append(max(0.1, self._weight(dt)))

        chosen_hour_index = random.choices(range(hours_span), weights=weights, k=1)[0]
        chosen_dt = start_dt + timedelta(
            hours=chosen_hour_index,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        ts = int((chosen_dt - self._tz_delta).timestamp())
        return min(max(ts, start_ts), end_ts)

    def pick_scenario(self, ts: int) -> str:
        """Pick a noise scenario biased by time buckets."""
        if not self.enabled:
            return random.choice(["dns_update", "vuln_scanner", "normal_login", "approved_backup", "red_team_scan"])

        dt = datetime.fromtimestamp(ts) + self._tz_delta
        weekday = dt.weekday()
        hour = dt.hour

        if (weekday == 6 and hour >= 20) or (weekday == 0 and hour <= 2):
            bucket = {
                "approved_backup": 4,
                "dns_update": 2,
                "vuln_scanner": 1,
                "normal_login": 1,
            }
        elif weekday < 5 and 8 <= hour <= 18:
            bucket = {
                "normal_login": 4,
                "vuln_scanner": 3,
                "dns_update": 2,
                "approved_backup": 1,
                "red_team_scan": 1,
            }
        elif weekday >= 5:
            bucket = {
                "approved_backup": 2,
                "dns_update": 2,
                "red_team_scan": 2,
                "vuln_scanner": 1,
                "normal_login": 1,
            }
        else:
            bucket = {
                "approved_backup": 2,
                "dns_update": 1,
                "red_team_scan": 2,
                "normal_login": 2,
                "vuln_scanner": 1,
            }

        scenarios = list(bucket.keys())
        weights = list(bucket.values())
        return random.choices(scenarios, weights=weights, k=1)[0]

