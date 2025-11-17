import csv
import os
import sqlite3
from typing import Any, Dict, List, Tuple

from dotenv import load_dotenv

load_dotenv()


def _safe_query(cursor: sqlite3.Cursor, query: str) -> List[Tuple[Any, ...]]:
    """Execute a query and return rows, swallowing SQLite errors for resilience."""
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except sqlite3.Error:
        return []


def _load_database_values() -> Dict[str, Any]:
    """Load IPs, categories, severities and other distributions from the alerts table."""
    db_path = os.getenv("DB_PATH", "/home/debian/DATABASE_FusionAI.db")
    if not os.path.exists(db_path):
        db_path = os.getenv("DB_PATH_FALLBACK", "/tmp/DATABASE_FusionAI.db")
    if not db_path or not os.path.exists(db_path):
        return {
            "source_ips": [],
            "dest_ips": [],
            "signatures": [],
            "categories_weighted": [],
            "severity_weighted": [],
            "real_src_ports": [],
            "real_dest_ports": [],
            "real_protocols": [],
        }

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    source_ips = [row[0] for row in _safe_query(cursor, "SELECT DISTINCT src_ip FROM alerts WHERE src_ip IS NOT NULL AND src_ip != ''") if row[0]]
    dest_ips = [row[0] for row in _safe_query(cursor, "SELECT DISTINCT dest_ip FROM alerts WHERE dest_ip IS NOT NULL AND dest_ip != ''") if row[0]]
    signatures = [row[0] for row in _safe_query(cursor, "SELECT DISTINCT signature FROM alerts WHERE signature IS NOT NULL AND signature != ''")]

    categories_distribution = _safe_query(cursor, "SELECT category, COUNT(*) as cnt FROM alerts WHERE category IS NOT NULL GROUP BY category")
    total_cats = sum([cnt for _, cnt in categories_distribution]) or 1
    categories_weighted = [(cat, cnt / total_cats) for cat, cnt in categories_distribution]

    severity_distribution = _safe_query(cursor, "SELECT severity, COUNT(*) as cnt FROM alerts WHERE severity IS NOT NULL GROUP BY severity")
    total_sev = sum([cnt for _, cnt in severity_distribution]) or 1
    severity_weighted = [(str(sev), cnt / total_sev) for sev, cnt in severity_distribution]

    real_src_ports = [row[0] for row in _safe_query(cursor, "SELECT DISTINCT src_port FROM alerts WHERE src_port IS NOT NULL AND src_port > 0 LIMIT 100")]
    real_dest_ports = [row[0] for row in _safe_query(cursor, "SELECT DISTINCT dest_port FROM alerts WHERE dest_port IS NOT NULL AND dest_port > 0 LIMIT 100")]
    real_protocols = [row[0] for row in _safe_query(cursor, "SELECT DISTINCT protocols FROM alerts WHERE protocols IS NOT NULL AND protocols != ''") if row[0]]

    conn.close()

    return {
        "source_ips": source_ips,
        "dest_ips": dest_ips,
        "signatures": signatures,
        "categories_weighted": categories_weighted,
        "severity_weighted": severity_weighted,
        "real_src_ports": real_src_ports,
        "real_dest_ports": real_dest_ports,
        "real_protocols": real_protocols,
    }


def _load_ad_users() -> List[Dict[str, str]]:
    """Load AD users or fallback to synthetic placeholders."""
    ad_users_file = os.getenv("AD_USERS_FILE", "/home/debian/ad_users.csv")
    if os.path.exists(ad_users_file):
        with open(ad_users_file, "r", encoding="utf-8") as f:
            return [row for row in csv.DictReader(f)]
    return [
        {"Username": f"user{i}", "Department": "IT", "Display_Name": f"User {i}", "Email": f"user{i}@fusionai.local"}
        for i in range(1, 101)
    ]


def _load_assets() -> List[Dict[str, str]]:
    """Load CMDB assets or fallback to small synthetic ones."""
    assets_file = os.getenv("CMDB_ASSETS_FILE", "/home/debian/cmdb_assets.csv")
    if os.path.exists(assets_file):
        with open(assets_file, "r", encoding="utf-8") as f:
            return [row for row in csv.DictReader(f)]
    return [
        {
            "Hostname": f"WKS-{i:03d}",
            "Asset_Type": "Workstation",
            "Criticality": "Medium",
            "Location": "Office",
            "IP_Address": f"10.0.1.{i}",
            "OS": "Windows 10 Pro" if i % 2 == 0 else "Ubuntu 22.04",
        }
        for i in range(1, 51)
    ]


def load_context() -> Dict[str, Any]:
    """Load all data sets required by the generator."""
    db_values = _load_database_values()
    ad_users = _load_ad_users()
    assets = _load_assets()

    ip_to_asset = {asset["IP_Address"]: asset for asset in assets if asset.get("IP_Address")}

    return {
        **db_values,
        "ad_users": ad_users,
        "assets": assets,
        "ip_to_asset": ip_to_asset,
    }
