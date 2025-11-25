#!/usr/bin/env python3
"""
Génération de 500 MB de données réalistes pour Elasticsearch
Utilise les vraies données de FusionAI, Assets CMDB et Users AD
"""

import json
import random
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv, find_dotenv
import sqlite3
import csv
import os
import sys

ROOT = Path(__file__).resolve().parent
for candidate in (ROOT, ROOT.parent):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from attack_chains.playbooks import PLAYBOOKS
from attack_chains.seasonal_noise import SeasonalNoiseModel

# Ensure we load the repo's scripts/.env even when invoked elsewhere
_DEFAULT_ENV = Path(__file__).resolve().parent / ".env"
load_dotenv(find_dotenv() or _DEFAULT_ENV)

# Configuration (fixed 500MB target to match original behavior)
TARGET_SIZE_MB = 500
TARGET_SIZE_BYTES = TARGET_SIZE_MB * 1024 * 1024
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100000"))  # Events par batch
OUTPUT_PREFIX = os.getenv("OUTPUT_PREFIX", "/home/debian/events_es_batch_")
def clamp_ratio(value):
    return min(max(value, 0.0), 0.95)


ATTACK_CHAIN_RATIO = clamp_ratio(float(os.getenv("ATTACK_CHAIN_RATIO", "0.15")))  # fraction d'événements dans une chaîne
NOISE_RATIO = clamp_ratio(float(os.getenv("NOISE_RATIO", "0.20")))  # fraction d'événements bruit/FP
ratio_warning = None
if ATTACK_CHAIN_RATIO + NOISE_RATIO > 0.95:
    scale = 0.95 / (ATTACK_CHAIN_RATIO + NOISE_RATIO)
    ATTACK_CHAIN_RATIO *= scale
    NOISE_RATIO *= scale
    ratio_warning = "[!] Ratios ajustés pour conserver des événements standards suffisants."

print("="*80)
print("🚀 GÉNÉRATEUR DE DONNÉES ELASTICSEARCH - FUSIONAI")
print("="*80)
print()

# Connexion à la base de données
DB_PATH = os.getenv("DB_PATH", "/home/debian/DATABASE_FusionAI.db")
if not os.path.exists(DB_PATH):
    DB_PATH = os.getenv("DB_PATH_FALLBACK", "/tmp/DATABASE_FusionAI.db")

print("[+] Connexion à la base de données FusionAI...")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Charger les données RÉELLES de la BDD
print("[+] Chargement des données RÉELLES depuis la BDD...")

# IPs sources RÉELLES
cursor.execute("SELECT DISTINCT src_ip FROM alerts WHERE src_ip IS NOT NULL AND src_ip != ''")
source_ips = [row[0] for row in cursor.fetchall() if row[0]]

# IPs destinations RÉELLES
cursor.execute("SELECT DISTINCT dest_ip FROM alerts WHERE dest_ip IS NOT NULL AND dest_ip != ''")
dest_ips = [row[0] for row in cursor.fetchall() if row[0]]

# Signatures d'attaques RÉELLES
cursor.execute("SELECT DISTINCT signature FROM alerts WHERE signature IS NOT NULL AND signature != ''")
signatures_real = [row[0] for row in cursor.fetchall()]

# Catégories RÉELLES avec leur distribution
cursor.execute("SELECT category, COUNT(*) as cnt FROM alerts WHERE category IS NOT NULL GROUP BY category")
categories_distribution = cursor.fetchall()
total_cats = sum([cnt for _, cnt in categories_distribution])
categories_weighted = []
for cat, cnt in categories_distribution:
    weight = cnt / total_cats
    categories_weighted.append((cat, weight))

# Sévérités RÉELLES avec distribution
cursor.execute("SELECT severity, COUNT(*) as cnt FROM alerts WHERE severity IS NOT NULL GROUP BY severity")
severity_distribution = cursor.fetchall()
total_sev = sum([cnt for _, cnt in severity_distribution])
severity_weighted = []
for sev, cnt in severity_distribution:
    weight = cnt / total_sev
    severity_weighted.append((str(sev), weight))

# Ports réels
cursor.execute("SELECT DISTINCT src_port FROM alerts WHERE src_port IS NOT NULL AND src_port > 0 LIMIT 100")
real_src_ports = [row[0] for row in cursor.fetchall()]

cursor.execute("SELECT DISTINCT dest_port FROM alerts WHERE dest_port IS NOT NULL AND dest_port > 0 LIMIT 100")
real_dest_ports = [row[0] for row in cursor.fetchall()]

# Protocoles réels
cursor.execute("SELECT DISTINCT protocols FROM alerts WHERE protocols IS NOT NULL AND protocols != ''")
real_protocols = [row[0] for row in cursor.fetchall() if row[0]]

print(f"    ✓ {len(source_ips)} IPs sources RÉELLES")
print(f"    ✓ {len(dest_ips)} IPs destinations RÉELLES")
print(f"    ✓ {len(signatures_real)} signatures RÉELLES")
print(f"    ✓ {len(categories_weighted)} catégories RÉELLES")
print(f"    ✓ Distribution sévérité RÉELLE")
print(f"    ✓ Ratio chaînes d'attaque: {ATTACK_CHAIN_RATIO}")
print(f"    ✓ Ratio bruit/FP: {NOISE_RATIO}")
if ratio_warning:
    print(f"    {ratio_warning}")

# Charger les utilisateurs AD RÉELS
print("[+] Chargement des utilisateurs AD...")
ad_users = []
ad_users_file = os.getenv("AD_USERS_FILE", "/home/debian/ad_users.csv")
if os.path.exists(ad_users_file):
    with open(ad_users_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        ad_users = [row for row in reader]
    print(f"    ✓ {len(ad_users)} utilisateurs AD RÉELS")
else:
    print("    ⚠ Fichier ad_users.csv non trouvé, utilisation de données par défaut")
    ad_users = [{'Username': f'user{i}', 'Department': 'IT', 'Display_Name': f'User {i}'}
                for i in range(1, 101)]

# Charger les assets CMDB RÉELS
print("[+] Chargement des assets CMDB...")
assets = []
assets_file = os.getenv("CMDB_ASSETS_FILE", "/home/debian/cmdb_assets.csv")
if os.path.exists(assets_file):
    with open(assets_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        assets = [row for row in reader]
    print(f"    ✓ {len(assets)} assets CMDB RÉELS")
else:
    print("    ⚠ Fichier cmdb_assets.csv non trouvé, utilisation de données par défaut")
    assets = [
        {'Hostname': f'WKS-{i:03d}', 'Asset_Type': 'Workstation',
         'Criticality': 'Medium', 'Location': 'Office', 'IP_Address': f'10.0.1.{i}'}
        for i in range(1, 101)
    ]

print()

# Créer un mapping IP -> Asset
ip_to_asset = {}
for asset in assets:
    if 'IP_Address' in asset and asset['IP_Address']:
        ip_to_asset[asset['IP_Address']] = asset

# Contexte (réutilisé pour les chaînes d'attaque)
chain_ctx = {
    "source_ips": source_ips,
    "dest_ips": dest_ips,
    "signatures": signatures_real,
    "categories_weighted": categories_weighted,
    "severity_weighted": severity_weighted,
    "real_src_ports": real_src_ports,
    "real_dest_ports": real_dest_ports,
    "real_protocols": real_protocols,
    "ad_users": ad_users,
    "assets": assets,
    "ip_to_asset": ip_to_asset,
}

# Période temporelle (étendre de 13 jours à 30 jours)
print("[+] Configuration temporelle:")
end_time = datetime.now()
start_time = end_time - timedelta(days=30)
print(f"    ✓ Période: {start_time.date()} à {end_time.date()}")
print()


def _progress_bar(current: int, total: int, width: int = 40) -> str:
    if total <= 0:
        return "[" + "." * width + "]  0.0%"
    pct = min(max(current / total, 0.0), 1.0)
    filled = int(pct * width)
    return f"[{'#' * filled}{'.' * (width - filled)}] {pct * 100:5.1f}%"


def _render_progress(current_bytes: int, total_bytes: int, total_events: int):
    bar = _progress_bar(current_bytes, total_bytes)
    sys.stdout.write(f"\rProgress {bar} ({total_events:,} events)")
    sys.stdout.flush()

# Fonction de sélection pondérée
def weighted_choice(choices_weights):
    """Sélectionne un élément selon une distribution pondérée"""
    choices, weights = zip(*choices_weights)
    total = sum(weights)
    r = random.uniform(0, total)
    upto = 0
    for choice, weight in zip(choices, weights):
        if upto + weight >= r:
            return choice
        upto += weight
    return choices[-1]


def build_event(timestamp, overrides=None):
    """Construit un événement ECS basique avec possibilité de forcer certains champs."""
    overrides = overrides or {}

    category = overrides.get("category") or weighted_choice(categories_weighted)
    severity = overrides.get("severity") or weighted_choice(severity_weighted)
    signature = overrides.get("signature") or random.choice(signatures_real)

    src_ip = overrides.get("src_ip") or random.choice(source_ips)
    dst_ip = overrides.get("dst_ip") or random.choice(dest_ips)

    asset = overrides.get("asset") or ip_to_asset.get(dst_ip) or random.choice(assets)
    user = overrides.get("user") or random.choice(ad_users)

    src_port = overrides.get("src_port") or (random.choice(real_src_ports) if real_src_ports else random.randint(49152, 65535))
    dest_port = overrides.get("dest_port") or (random.choice(real_dest_ports) if real_dest_ports else random.choice([80, 443, 445, 3389, 22]))
    protocol = overrides.get("protocol") or (random.choice(real_protocols) if real_protocols else "TCP")

    action = overrides.get("action") or random.choice(["allowed", "blocked", "logged"])
    if "outcome" in overrides:
        outcome = overrides["outcome"]
    elif action == "blocked":
        outcome = "failure"
    elif action == "allowed":
        outcome = "success"
    else:
        outcome = random.choice(["success", "failure", "unknown"])

    direction = overrides.get("direction") or random.choice(["inbound", "outbound", "internal"])

    dt = datetime.fromtimestamp(timestamp)
    severity_map = {
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical"
    }
    severity_text = severity_map.get(str(severity), "medium")

    mitre_map = {
        "malcore": ("T1059", "Execution"),
        "sigflow_alert": ("T1071", "Command and Control"),
        "dga_detect": ("T1568", "Command and Control"),
        "malicious_powershell_detect": ("T1059.001", "Execution"),
        "shellcode_detect": ("T1055", "Defense Evasion"),
        "retrohunt": ("T1087", "Discovery")
    }
    mitre_technique, mitre_tactic = mitre_map.get(category, ("T1071", "Unknown"))

    event = {
        "@timestamp": dt.isoformat(),
        "event": {
            "category": "security",
            "type": "alert",
            "kind": "alert",
            "severity": severity_text,
            "action": action,
            "outcome": outcome,
            "module": category,
            "dataset": "fusionai.alerts"
        },
        "source": {
            "ip": src_ip,
            "port": src_port,
            "bytes": random.randint(100, 50000)
        },
        "destination": {
            "ip": dst_ip,
            "port": dest_port,
            "bytes": random.randint(500, 100000)
        },
        "network": {
            "protocol": protocol.lower() if protocol else "tcp",
            "bytes": random.randint(600, 150000),
            "direction": direction
        },
        "user": {
            "name": user.get('Username', 'unknown'),
            "domain": overrides.get("user_domain", "fusionai.local"),
            "email": user.get('Email', ''),
            "department": user.get('Department', 'Unknown'),
            "full_name": user.get('Display_Name', '')
        },
        "host": {
            "name": asset.get('Hostname', 'unknown'),
            "hostname": asset.get('Hostname', 'unknown'),
            "type": asset.get('Asset_Type', 'Unknown'),
            "ip": [dst_ip],
            "mac": [asset.get('MAC_Address', '')] if asset.get('MAC_Address') else [],
            "os": {
                "name": asset.get('OS', 'Unknown'),
                "platform": "linux" if "Linux" in asset.get('OS', '') or "Ubuntu" in asset.get('OS', '') else "windows"
            },
            "risk": {
                "static_level": asset.get('Criticality', 'Medium').lower()
            }
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": {
                "id": [mitre_technique],
                "name": [category]
            },
            "tactic": {
                "name": [mitre_tactic]
            }
        },
        "rule": {
            "name": signature,
            "category": category,
            "id": overrides.get("rule_id") or str(random.randint(1000, 9999))
        },
        "fusionai": {
            "signature": signature,
            "category": category,
            "severity": severity,
            "asset_owner": asset.get('Owner', ''),
            "asset_location": asset.get('Location', ''),
            "asset_department": asset.get('Department', '')
        },
        "tags": [
            category,
            severity_text,
            "fusionai",
            asset.get('Location', 'unknown').lower().replace(' ', '_')
        ],
        "labels": {
            "env": "production",
            "source": "fusionai_generator",
            "data_source": "real_fusion_ai"
        }
    }

    if overrides.get("attack"):
        event["attack"] = overrides["attack"]

    # Ajouter des champs spécifiques selon la catégorie
    if "powershell" in category.lower():
        event["process"] = {
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -enc " + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", k=50))
        }

    if "dga" in category.lower():
        domain_length = random.randint(10, 20)
        dga_domain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=domain_length)) + ".com"
        event["dns"] = {
            "question": {
                "name": dga_domain,
                "type": "A"
            }
        }

    if "scan" in signature.lower() or "port_scan" in category.lower():
        event["fusionai"]["scan_type"] = random.choice(["TCP SYN", "TCP ACK", "UDP", "XMAS"])
        event["fusionai"]["ports_scanned"] = random.randint(50, 5000)

    return event


def generate_event(timestamp):
    """Génère un événement réaliste basé sur les VRAIES données FusionAI"""
    return build_event(timestamp)


def generate_noise_event(timestamp):
    """Crée un faux positif ou une alerte bénigne pour polluer légèrement les données."""
    scenario = random.choice(["dns_update", "internal_scanner", "admin_login"])
    if scenario == "dns_update":
        overrides = {
            "category": "benign_dns_activity",
            "signature": "Windows Update DNS Lookup",
            "severity": "1",
            "action": "logged",
            "outcome": "success",
            "direction": "outbound"
        }
    elif scenario == "internal_scanner":
        overrides = {
            "category": "false_positive_scan",
            "signature": "Internal vulnerability scanner",
            "severity": "2",
            "action": "blocked",
            "outcome": "failure",
            "direction": "internal"
        }
    else:
        overrides = {
            "category": "benign_user_activity",
            "signature": "Known admin login",
            "severity": "1",
            "action": "allowed",
            "outcome": "success",
            "direction": "internal"
        }

    event = build_event(timestamp, overrides)
    event["fusionai"]["noise"] = True
    event["tags"].append("noise")
    event["labels"]["noise_type"] = scenario

    if scenario == "dns_update":
        domain = f"windowsupdate.{random.choice(['microsoft.com', 'windows.com'])}"
        event["dns"] = {
            "question": {
                "name": domain,
                "type": "A"
            }
        }
    elif scenario == "internal_scanner":
        event["fusionai"]["scan_type"] = "internal_compliance"
        event["fusionai"]["ports_scanned"] = random.randint(10, 250)
    else:
        event["logon"] = {"type": "network", "status": "success", "method": "kerberos"}

    return event


def generate_attack_chain(start_ts: int, end_ts: int, seasonal: SeasonalNoiseModel):
    """Construit une chaîne d'attaque corrélée via les playbooks existants."""
    attack_id = f"attack-{uuid.uuid4().hex[:10]}"
    chain_start = seasonal.pick_alert_timestamp(start_ts, end_ts) if seasonal else random.randint(start_ts, end_ts)
    playbook = random.choice(PLAYBOOKS)
    return playbook(chain_ctx, attack_id, chain_start)

# Génération des événements
print("="*80)
print(f"🔄 GÉNÉRATION DE {TARGET_SIZE_MB} MB D'ÉVÉNEMENTS RÉALISTES")
print("="*80)
print()

total_bytes = 0
total_events = 0
chain_count = 0
chain_events_total = 0
noise_events = 0
batch_num = 1
batch_events = []
progress_last = 0

seasonal_model = SeasonalNoiseModel()
start_ts = int(start_time.timestamp())
end_ts = int(end_time.timestamp())

start_gen_time = time.time()

try:
    _render_progress(0, TARGET_SIZE_BYTES, 0)
    while total_bytes < TARGET_SIZE_BYTES:
        # Générer soit une chaîne, soit un événement unique, soit du bruit
        pick = random.random()
        if pick < NOISE_RATIO:
            timestamp = seasonal_model.pick_timestamp(start_ts, end_ts) if seasonal_model.enabled else random.randint(start_ts, end_ts)
            event = generate_noise_event(timestamp)
            batch_events.append(event)
            total_events += 1
            noise_events += 1
        elif pick < NOISE_RATIO + ATTACK_CHAIN_RATIO:
            chain_events = generate_attack_chain(start_ts, end_ts, seasonal_model if seasonal_model.enabled else None)
            chain_count += 1
            chain_events_total += len(chain_events)
            for evt in chain_events:
                batch_events.append(evt)
                total_events += 1
                if len(batch_events) >= BATCH_SIZE:
                    filename = f"{OUTPUT_PREFIX}{batch_num:04d}.json"
                    with open(filename, 'w') as f:
                        for e in batch_events:
                            f.write(json.dumps(e) + '\n')
                    batch_size = os.path.getsize(filename)
                    total_bytes += batch_size
                    elapsed = time.time() - start_gen_time
                    rate = total_events / elapsed if elapsed > 0 else 0
                    print(f"    Batch {batch_num:04d}: {len(batch_events):,} événements, {batch_size/1024/1024:.1f} MB")
                    print(f"               Total: {total_bytes/1024/1024:.1f} / {TARGET_SIZE_MB} MB ({total_events:,} events, {rate:.0f} events/s)")
                    _render_progress(total_bytes, TARGET_SIZE_BYTES, total_events)
                    batch_events = []
                    batch_num += 1
                    if total_bytes >= TARGET_SIZE_BYTES:
                        break
        else:
            timestamp = (
                seasonal_model.pick_alert_timestamp(start_ts, end_ts)
                if seasonal_model.enabled
                else random.randint(start_ts, end_ts)
            )
            event = generate_event(timestamp)
            batch_events.append(event)
            total_events += 1

        # Sauvegarder le batch si atteint
        if len(batch_events) >= BATCH_SIZE:
            filename = f"{OUTPUT_PREFIX}{batch_num:04d}.json"
            with open(filename, 'w') as f:
                for evt in batch_events:
                    f.write(json.dumps(evt) + '\n')

            # Calculer la taille
            batch_size = os.path.getsize(filename)
            total_bytes += batch_size

            elapsed = time.time() - start_gen_time
            rate = total_events / elapsed if elapsed > 0 else 0

            print(f"    Batch {batch_num:04d}: {len(batch_events):,} événements, {batch_size/1024/1024:.1f} MB")
            print(f"               Total: {total_bytes/1024/1024:.1f} / {TARGET_SIZE_MB} MB ({total_events:,} events, {rate:.0f} events/s)")
            _render_progress(total_bytes, TARGET_SIZE_BYTES, total_events)

            batch_events = []
            batch_num += 1

            # Vérifier si on dépasse la cible
            if total_bytes >= TARGET_SIZE_BYTES:
                break
        elif total_events - progress_last >= 5000:
            progress_last = total_events
            _render_progress(total_bytes, TARGET_SIZE_BYTES, total_events)

    # Sauvegarder le dernier batch si nécessaire
    if batch_events and total_bytes < TARGET_SIZE_BYTES:
        filename = f"{OUTPUT_PREFIX}{batch_num:04d}.json"
        with open(filename, 'w') as f:
            for evt in batch_events:
                f.write(json.dumps(evt) + '\n')

        batch_size = os.path.getsize(filename)
        total_bytes += batch_size

        print(f"    Batch {batch_num:04d}: {len(batch_events):,} événements, {batch_size/1024/1024:.1f} MB (Final)")
        _render_progress(total_bytes, TARGET_SIZE_BYTES, total_events)

except Exception as e:
    print(f"\n[!] Erreur: {e}")
    import traceback
    traceback.print_exc()

finally:
    conn.close()

total_time = time.time() - start_gen_time

sys.stdout.write("\n")
print()
print("="*80)
print("✅ GÉNÉRATION TERMINÉE")
print("="*80)
print(f"Total événements:    {total_events:,}")
print(f"Total fichiers:      {batch_num}")
print(f"Taille totale:       {total_bytes/1024/1024:.2f} MB")
print(f"Temps:               {total_time:.1f}s")
print(f"Vitesse:             {total_events/total_time:.0f} événements/s")
print(f"Fichiers:            {OUTPUT_PREFIX}0001.json à {OUTPUT_PREFIX}{batch_num:04d}.json")
chain_pct = (chain_events_total / total_events * 100) if total_events else 0
noise_pct = (noise_events / total_events * 100) if total_events else 0
print(f"Chaînes générées:    {chain_count} (événements corrélés: {chain_events_total}, {chain_pct:.1f}% du total)")
print(f"Bruit / FP:          {noise_events} événements ({noise_pct:.1f}% du total)")
print()
print("Caractéristiques:")
print(f"  • {len(source_ips)} IPs sources RÉELLES de FusionAI")
print(f"  • {len(dest_ips)} IPs destinations RÉELLES de FusionAI")
print(f"  • {len(signatures_real)} signatures RÉELLES")
print(f"  • {len(ad_users)} utilisateurs AD RÉELS")
print(f"  • {len(assets)} assets CMDB RÉELS")
print(f"  • Distribution de sévérité RÉELLE")
print(f"  • Catégories RÉELLES (malcore, sigflow_alert, dga_detect, etc.)")
print()
