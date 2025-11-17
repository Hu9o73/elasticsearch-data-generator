#!/usr/bin/env python3
"""
Génération de 500 MB de données réalistes pour Elasticsearch
Utilise les vraies données de FusionAI, Assets CMDB et Users AD
"""

import json
import random
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
import sqlite3
import csv
import os

load_dotenv()

# Configuration
TARGET_SIZE_MB = 500
TARGET_SIZE_BYTES = TARGET_SIZE_MB * 1024 * 1024
BATCH_SIZE = 100000  # Events par batch
OUTPUT_PREFIX = os.getenv("OUTPUT_PREFIX", "/home/debian/events_es_batch_")

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

# Période temporelle (étendre de 13 jours à 30 jours)
print("[+] Configuration temporelle:")
end_time = datetime.now()
start_time = end_time - timedelta(days=30)
print(f"    ✓ Période: {start_time.date()} à {end_time.date()}")
print()

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

def generate_event(timestamp):
    """Génère un événement réaliste basé sur les VRAIES données FusionAI"""

    # Utiliser les distributions RÉELLES
    category = weighted_choice(categories_weighted)
    severity = weighted_choice(severity_weighted)
    signature = random.choice(signatures_real)

    # IPs RÉELLES
    src_ip = random.choice(source_ips)
    dst_ip = random.choice(dest_ips)

    # Trouver l'asset correspondant à l'IP destination
    asset = ip_to_asset.get(dst_ip)
    if not asset:
        asset = random.choice(assets)

    # User aléatoire
    user = random.choice(ad_users)

    # Ports réels
    src_port = random.choice(real_src_ports) if real_src_ports else random.randint(49152, 65535)
    dest_port = random.choice(real_dest_ports) if real_dest_ports else random.choice([80, 443, 445, 3389, 22])

    # Protocole réel
    protocol = random.choice(real_protocols) if real_protocols else "TCP"

    # Timestamp ISO 8601
    dt = datetime.fromtimestamp(timestamp)

    # Mapper sévérité numérique vers texte
    severity_map = {
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical"
    }
    severity_text = severity_map.get(str(severity), "medium")

    # Mapper catégorie vers technique MITRE (approximatif)
    mitre_map = {
        "malcore": ("T1059", "Execution"),
        "sigflow_alert": ("T1071", "Command and Control"),
        "dga_detect": ("T1568", "Command and Control"),
        "malicious_powershell_detect": ("T1059.001", "Execution"),
        "shellcode_detect": ("T1055", "Defense Evasion"),
        "retrohunt": ("T1087", "Discovery")
    }

    mitre_technique, mitre_tactic = mitre_map.get(category, ("T1071", "Unknown"))

    # Construire l'événement au format ECS
    event = {
        "@timestamp": dt.isoformat(),

        # Event metadata
        "event": {
            "category": "security",
            "type": "alert",
            "kind": "alert",
            "severity": severity_text,
            "action": random.choice(["allowed", "blocked", "logged"]),
            "outcome": random.choice(["success", "failure", "unknown"]),
            "module": category,
            "dataset": "fusionai.alerts"
        },

        # Network data
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
            "direction": random.choice(["inbound", "outbound", "internal"])
        },

        # User info
        "user": {
            "name": user.get('Username', 'unknown'),
            "domain": "fusionai.local",
            "email": user.get('Email', ''),
            "department": user.get('Department', 'Unknown'),
            "full_name": user.get('Display_Name', '')
        },

        # Host/Asset info
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

        # Threat intel - MITRE ATT&CK
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

        # Alert/Security data
        "rule": {
            "name": signature,
            "category": category,
            "id": str(random.randint(1000, 9999))
        },

        # FusionAI specific fields
        "fusionai": {
            "signature": signature,
            "category": category,
            "severity": severity,
            "asset_owner": asset.get('Owner', ''),
            "asset_location": asset.get('Location', ''),
            "asset_department": asset.get('Department', '')
        },

        # Tags
        "tags": [
            category,
            severity_text,
            "fusionai",
            asset.get('Location', 'unknown').lower().replace(' ', '_')
        ],

        # Labels
        "labels": {
            "env": "production",
            "source": "fusionai_generator",
            "data_source": "real_fusion_ai"
        }
    }

    # Ajouter des champs spécifiques selon la catégorie
    if "powershell" in category.lower():
        event["process"] = {
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -enc " + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", k=50))
        }

    if "dga" in category.lower():
        # DGA domain
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

# Génération des événements
print("="*80)
print(f"🔄 GÉNÉRATION DE {TARGET_SIZE_MB} MB D'ÉVÉNEMENTS RÉALISTES")
print("="*80)
print()

total_bytes = 0
total_events = 0
batch_num = 1
batch_events = []

start_ts = int(start_time.timestamp())
end_ts = int(end_time.timestamp())

start_gen_time = time.time()

try:
    while total_bytes < TARGET_SIZE_BYTES:
        # Timestamp aléatoire dans les 30 derniers jours
        timestamp = random.randint(start_ts, end_ts)

        # Générer événement
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

            batch_events = []
            batch_num += 1

            # Vérifier si on dépasse la cible
            if total_bytes >= TARGET_SIZE_BYTES:
                break

    # Sauvegarder le dernier batch si nécessaire
    if batch_events and total_bytes < TARGET_SIZE_BYTES:
        filename = f"{OUTPUT_PREFIX}{batch_num:04d}.json"
        with open(filename, 'w') as f:
            for evt in batch_events:
                f.write(json.dumps(evt) + '\n')

        batch_size = os.path.getsize(filename)
        total_bytes += batch_size

        print(f"    Batch {batch_num:04d}: {len(batch_events):,} événements, {batch_size/1024/1024:.1f} MB (Final)")

except Exception as e:
    print(f"\n[!] Erreur: {e}")
    import traceback
    traceback.print_exc()

finally:
    conn.close()

total_time = time.time() - start_gen_time

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
