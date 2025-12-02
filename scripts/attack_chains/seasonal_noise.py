import math
import os
import random
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import List, Optional, Sequence

DAY_HOURS = list(range(8, 19))  # 08:00-18:00 inclusive
DEFAULT_NOISE_DAY_WEIGHT = 20.0
DEFAULT_NOISE_MAINT_WEIGHT = 15.0
DEFAULT_NOISE_WEEKEND_WEIGHT = 0.2
DEFAULT_NOISE_EARLY_WEIGHT = 0.1
DEFAULT_NOISE_DEFAULT_WEIGHT = 3.0
DEFAULT_NOISE_DAY_SHARE = 0.7

DEFAULT_ALERT_NIGHT_WEIGHT = 12.0
DEFAULT_ALERT_EVENING_WEIGHT = 8.0
DEFAULT_ALERT_WEEKEND_WEIGHT = 2.0
DEFAULT_ALERT_DAY_WEIGHT = 0.3
DEFAULT_ALERT_DEFAULT_WEIGHT = 0.8


def _build_hourly_curve(peak_hour: int, min_scale: float, max_scale: float) -> List[float]:
    """Smooth sinusoid peaking at `peak_hour`, scaled into [min_scale, max_scale]."""
    phase_shift = 2 * math.pi * peak_hour / 24 - math.pi / 2
    curve: List[float] = []
    for hour in range(24):
        norm = (math.sin(2 * math.pi * (hour / 24) - phase_shift) + 1) / 2  # 0..1
        curve.append(min_scale + norm * (max_scale - min_scale))
    return curve


def _rebalance_day_share(weights: List[float], target_share: float) -> List[float]:
    """Scale night vs day weights so the day window carries ~target_share mass."""
    target = min(max(target_share, 0.01), 0.99)
    day_sum = sum(weights[h] for h in DAY_HOURS)
    total = sum(weights)
    night_sum = total - day_sum
    if total <= 0 or night_sum <= 0:
        return weights

    night_factor = (day_sum * (1 - target)) / (night_sum * target)
    adjusted: List[float] = []
    for hour, w in enumerate(weights):
        if hour in DAY_HOURS:
            adjusted.append(max(0.01, w))
        else:
            adjusted.append(max(0.01, w * night_factor))

    # Normalize so average weight stays ~1.0
    scale = len(adjusted) / sum(adjusted)
    return [w * scale for w in adjusted]


# Default shapes if no env override: strong day swell for noise, night swell for alerts.
# Values are intentionally outrageous so any seasonality bug is obvious in histograms.
_DEFAULT_NOISE_BASE = _build_hourly_curve(peak_hour=14, min_scale=0.2, max_scale=1.6)
DEFAULT_NOISE_HOURLY_SHAPE: List[float] = _rebalance_day_share(_DEFAULT_NOISE_BASE, target_share=DEFAULT_NOISE_DAY_SHARE)
DEFAULT_ALERT_HOURLY_SHAPE: List[float] = _build_hourly_curve(peak_hour=2, min_scale=0.1, max_scale=7.5)


def _enabled_from_env() -> bool:
    val = os.getenv("NOISE_SEASONALITY", "on").lower()
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
    noise_hourly: Optional[List[float]] = None
    alert_hourly: Optional[List[float]] = None
    noise_day_weight: float = None
    noise_maintenance_weight: float = None
    noise_weekend_weight: float = None
    noise_early_weight: float = None
    noise_default_weight: float = None
    noise_day_share: float = None
    alert_night_weight: float = None
    alert_evening_weight: float = None
    alert_weekend_weight: float = None
    alert_day_weight: float = None
    alert_default_weight: float = None

    def __post_init__(self) -> None:
        if self.enabled is None:
            self.enabled = _enabled_from_env()
        if self.tz_offset_hours is None:
            self.tz_offset_hours = _tz_offset_from_env()
        self._tz_delta = timedelta(hours=self.tz_offset_hours)
        self._noise_cdf: Sequence[float] = ()
        self._alert_cdf: Sequence[float] = ()

        def _hourly_env(name: str) -> Optional[List[float]]:
            raw = os.getenv(name, "").strip()
            if not raw:
                return None
            parts = raw.split(",")
            if len(parts) != 24:
                return None
            values: List[float] = []
            for p in parts:
                try:
                    values.append(float(p))
                except ValueError:
                    return None
            return values

        # Fixed defaults (no .env override) to ensure consistent seasonality.
        self.noise_day_weight = self.noise_day_weight or DEFAULT_NOISE_DAY_WEIGHT
        self.noise_maintenance_weight = self.noise_maintenance_weight or DEFAULT_NOISE_MAINT_WEIGHT
        self.noise_weekend_weight = self.noise_weekend_weight or DEFAULT_NOISE_WEEKEND_WEIGHT
        self.noise_early_weight = self.noise_early_weight or DEFAULT_NOISE_EARLY_WEIGHT
        self.noise_default_weight = self.noise_default_weight or DEFAULT_NOISE_DEFAULT_WEIGHT
        self.noise_day_share = self.noise_day_share or DEFAULT_NOISE_DAY_SHARE
        self.noise_hourly = _hourly_env("NOISE_HOURLY_WEIGHTS")
        if self.noise_hourly:
            self._noise_hourly_shape = self.noise_hourly
        else:
            base = _build_hourly_curve(peak_hour=14, min_scale=0.2, max_scale=1.6)
            self._noise_hourly_shape = _rebalance_day_share(base, target_share=self.noise_day_share)

        self.alert_night_weight = self.alert_night_weight or DEFAULT_ALERT_NIGHT_WEIGHT
        self.alert_evening_weight = self.alert_evening_weight or DEFAULT_ALERT_EVENING_WEIGHT
        self.alert_weekend_weight = self.alert_weekend_weight or DEFAULT_ALERT_WEEKEND_WEIGHT
        self.alert_day_weight = self.alert_day_weight or DEFAULT_ALERT_DAY_WEIGHT
        self.alert_default_weight = self.alert_default_weight or DEFAULT_ALERT_DEFAULT_WEIGHT
        self.alert_hourly = _hourly_env("ALERT_HOURLY_WEIGHTS")
        self._alert_hourly_shape = self.alert_hourly or DEFAULT_ALERT_HOURLY_SHAPE
        self._noise_cdf = self._build_cdf(self._noise_hourly_shape)
        self._alert_cdf = self._build_cdf(self._alert_hourly_shape)

    @staticmethod
    def _build_cdf(prob: Sequence[float]) -> List[float]:
        total = sum(prob)
        if total <= 0:
            return [i / 24 for i in range(1, 25)]
        cdf: List[float] = []
        acc = 0.0
        for w in prob:
            acc += w / total
            cdf.append(acc)
        cdf[-1] = 1.0  # ensure last entry is exact
        return cdf

    @staticmethod
    def _sample_hour(cdf: Sequence[float]) -> int:
        r = random.random()
        for idx, cut in enumerate(cdf):
            if r <= cut:
                return idx
        return 23

    def _pick_weighted_timestamp(self, start_ts: int, end_ts: int, cdf: Sequence[float]) -> int:
        if end_ts <= start_ts:
            return start_ts

        # Work in tz-adjusted dates to keep hour selection consistent.
        start_dt = datetime.fromtimestamp(start_ts) + self._tz_delta
        end_dt = datetime.fromtimestamp(end_ts) + self._tz_delta
        start_date = start_dt.date()
        end_date = end_dt.date()
        day_span = (end_date - start_date).days
        day_span = max(day_span, 0)

        for _ in range(10):  # bounded retries to stay within window edges
            day_offset = random.randint(0, day_span)
            target_date = start_date + timedelta(days=day_offset)
            hour = self._sample_hour(cdf)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            candidate = datetime.combine(target_date, time(hour, minute, second)) - self._tz_delta
            ts = int(candidate.timestamp())
            if start_ts <= ts <= end_ts:
                return ts

        # Fallback: clamp a last candidate to bounds
        ts = int(candidate.timestamp())
        return min(max(ts, start_ts), end_ts)

    def pick_timestamp(self, start_ts: int, end_ts: int) -> int:
        """Draw a timestamp with seasonality weighting; fallback to uniform."""
        if not self.enabled:
            return random.randint(start_ts, end_ts)
        return self._pick_weighted_timestamp(start_ts, end_ts, self._noise_cdf)

    def pick_alert_timestamp(self, start_ts: int, end_ts: int) -> int:
        """Pick timestamp for non-noise alerts, biasing toward night-time peaks."""
        if not self.enabled:
            return random.randint(start_ts, end_ts)
        return self._pick_weighted_timestamp(start_ts, end_ts, self._alert_cdf)

    def pick_scenario(self, ts: int) -> str:
        """Pick a noise scenario biased by time buckets."""
        if not self.enabled:
            return random.choice(["dns_update", "vuln_scanner", "normal_login", "approved_backup", "red_team_scan"])

        dt = datetime.fromtimestamp(ts) + self._tz_delta
        weekday = dt.weekday()
        hour = dt.hour

        if (weekday == 6 and hour >= 20) or (weekday == 0 and hour <= 2):
            bucket = {
                "approved_backup": 8,
                "dns_update": 3,
                "vuln_scanner": 3,
                "normal_login": 1,
            }
        elif weekday < 5 and 8 <= hour <= 18:
            bucket = {
                "normal_login": 6,
                "vuln_scanner": 4,
                "dns_update": 3,
                "approved_backup": 1,
                "red_team_scan": 1,
            }
        elif weekday >= 5:
            bucket = {
                "approved_backup": 4,
                "dns_update": 3,
                "red_team_scan": 2,
                "vuln_scanner": 2,
                "normal_login": 1,
            }
        else:
            bucket = {
                "approved_backup": 3,
                "dns_update": 2,
                "red_team_scan": 2,
                "normal_login": 2,
                "vuln_scanner": 2,
            }

        scenarios = list(bucket.keys())
        weights = list(bucket.values())
        return random.choices(scenarios, weights=weights, k=1)[0]
