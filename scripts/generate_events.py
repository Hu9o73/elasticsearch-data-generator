#!/usr/bin/env python3
"""
Génération de 500 MB de données réalistes pour Elasticsearch
Générateur d'événements de sécurité pour SIEM/SOC testing
"""

import json
import random
import time
from datetime import datetime, timedelta
import sqlite3
import csv
import os

# Configuration
TARGET_SIZE_MB = 500
TARGET_SIZE_BYTES = TARGET_SIZE_MB * 1024 * 1024
BATCH_SIZE = 100000  # Events par batch
OUTPUT_PREFIX = "/home/debian/events_es_batch_"

# Connexion à la base de données
DB_PATH = '/tmp/DATABASE_FusionAI.db'
if not os.path.exists(DB_PATH):
    DB_PATH = '/home/debian/DATABASE_FusionAI.db'

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Charger les données
print("[+] Chargement des données de référence...")

# IPs depuis la BDD
cursor.execute("SELECT DISTINCT src_ip FROM alerts WHERE src_ip IS NOT NULL")
source_ips = [row[0] for row in cursor.fetchall() if row[0]]
cursor.execute("SELECT DISTINCT dest_ip FROM alerts WHERE dest_ip IS NOT NULL")
dest_ips = [row[0] for row in cursor.fetchall() if row[0]]

# Users - vérifier si le fichier existe
ad_users = []
ad_users_file = '/home/debian/ad_users.csv'
if os.path.exists(ad_users_file):
    with open(ad_users_file, 'r') as f:
        reader = csv.DictReader(f)
        ad_users = [row for row in reader]
else:
    # Créer des utilisateurs par défaut
    ad_users = [
        {'Username': f'user{i}', 'Department': random.choice(['IT', 'Finance', 'HR', 'Sales']),
         'Display_Name': f'User {i}'}
        for i in range(1, 101)
    ]

# Assets - vérifier si le fichier existe
assets = []
assets_file = '/home/debian/cmdb_assets.csv'
if os.path.exists(assets_file):
    with open(assets_file, 'r') as f:
        reader = csv.DictReader(f)
        assets = [row for row in reader]
else:
    # Créer des assets par défaut
    assets = [
        {
            'Hostname': f'WKS-{i:03d}',
            'Asset_Type': random.choice(['Workstation', 'Server', 'Laptop']),
            'Criticality': random.choice(['Low', 'Medium', 'High', 'Critical']),
            'Location': random.choice(['Building A', 'Building B', 'Remote'])
        }
        for i in range(1, 101)
    ]

# Signatures d'attaques depuis la BDD
cursor.execute("SELECT DISTINCT signature FROM alerts WHERE signature IS NOT NULL")
signatures = [row[0] for row in cursor.fetchall()]

print(f"    {len(source_ips)} source IPs")
print(f"    {len(dest_ips)} destination IPs")
print(f"    {len(ad_users)} utilisateurs AD")
print(f"    {len(assets)} assets CMDB")
print(f"    {len(signatures)} signatures d'attaque")
print()

# Patterns d'attaques
attack_patterns = [
    {
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "signatures": ["SQL Injection Attempt", "Malicious SQL Query", "SQL Syntax Error"],
        "techniques": ["T1190", "T1189"],
        "tactic": "Initial Access",
        "urls": [
            "/admin/login.php?user=admin' OR '1'='1",
            "/search.asp?q=1' UNION SELECT password FROM users--",
            "/product.jsp?id=1; DROP TABLE customers--"
        ]
    },
    {
        "name": "XSS Attack",
        "severity": "HIGH",
        "signatures": ["Cross-Site Scripting", "Malicious JavaScript Injection"],
        "techniques": ["T1189", "T1203"],
        "tactic": "Initial Access",
        "urls": [
            "/search?q=<script>alert('XSS')</script>",
            "/comment.php?text=<img src=x onerror=alert(1)>",
            "/profile?name=<script>document.cookie</script>"
        ]
    },
    {
        "name": "Lateral Movement",
        "severity": "CRITICAL",
        "signatures": ["SMB Lateral Movement", "RDP Brute Force", "Pass-the-Hash"],
        "techniques": ["T1021", "T1550"],
        "tactic": "Lateral Movement",
        "ports": [445, 3389, 135]
    },
    {
        "name": "Data Exfiltration",
        "severity": "CRITICAL",
        "signatures": ["DNS Exfiltration", "Large Data Transfer", "Suspicious FTP Upload"],
        "techniques": ["T1048", "T1041"],
        "tactic": "Exfiltration",
        "protocols": ["DNS", "FTP", "HTTPS"]
    },
    {
        "name": "Reconnaissance",
        "severity": "MEDIUM",
        "signatures": ["Port Scan Detected", "Network Enumeration", "LDAP Query"],
        "techniques": ["T1046", "T1087"],
        "tactic": "Discovery",
        "ports": [22, 80, 443, 3389, 445, 8080]
    }
]

def generate_event(timestamp, event_type="security"):
    """Génère un événement réaliste pour Elasticsearch"""

    pattern = random.choice(attack_patterns)
    src_ip = random.choice(source_ips)
    dst_ip = random.choice(dest_ips)
    user = random.choice(ad_users)
    asset = random.choice(assets)

    # Timestamp au format ISO 8601 pour Elasticsearch
    dt = datetime.fromtimestamp(timestamp)

    event = {
        "@timestamp": dt.isoformat(),
        "event": {
            "category": event_type,
            "type": "security_event",
            "kind": "alert",
            "severity": pattern["severity"].lower(),
            "action": random.choice(["allowed", "blocked", "logged"]),
            "outcome": random.choice(["success", "failure", "unknown"])
        },

        # Network data
        "source": {
            "ip": src_ip,
            "port": random.randint(49152, 65535),
            "bytes": random.randint(100, 10000)
        },
        "destination": {
            "ip": dst_ip,
            "port": random.choice(pattern.get("ports", [80, 443, 445])),
            "bytes": random.randint(500, 50000)
        },
        "network": {
            "protocol": random.choice(["tcp", "udp", "icmp"]),
            "bytes": random.randint(600, 60000),
            "direction": random.choice(["inbound", "outbound", "internal"])
        },

        # User & Host (ECS format)
        "user": {
            "name": user['Username'],
            "domain": "CORP",
            "department": user.get('Department', 'Unknown')
        },
        "host": {
            "name": asset['Hostname'],
            "type": asset.get('Asset_Type', 'Unknown'),
            "risk_level": asset.get('Criticality', 'Medium').lower()
        },

        # Threat intelligence
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": {
                "id": random.choice(pattern["techniques"]),
                "name": pattern["name"]
            },
            "tactic": {
                "name": pattern["tactic"]
            }
        },

        # Attack data
        "security": {
            "signature": random.choice(pattern["signatures"]),
            "category": pattern["name"],
            "severity": pattern["severity"]
        },

        # Metadata
        "tags": [event_type, pattern["severity"].lower(), "generated"],
        "labels": {
            "env": "test",
            "source": "fusionai_generator"
        }
    }

    # Ajouter des champs spécifiques selon le type d'attaque
    if pattern["name"] in ["SQL Injection", "XSS Attack"]:
        event["url"] = {
            "original": random.choice(pattern["urls"]),
            "path": random.choice(pattern["urls"]).split('?')[0]
        }
        event["http"] = {
            "request": {
                "method": random.choice(["GET", "POST"]),
                "bytes": random.randint(200, 5000)
            },
            "response": {
                "status_code": random.choice([200, 403, 500, 401]),
                "bytes": random.randint(500, 50000)
            }
        }
        event["user_agent"] = {
            "original": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "sqlmap/1.4.7",
                "python-requests/2.25.1"
            ])
        }

    if pattern["name"] == "Lateral Movement":
        event["process"] = {
            "name": random.choice(["mstsc.exe", "net.exe", "powershell.exe"]),
            "executable": random.choice([
                "C:\\Windows\\System32\\mstsc.exe",
                "C:\\Windows\\System32\\net.exe",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            ]),
            "command_line": random.choice([
                "mstsc.exe /v:10.0.1.50",
                "net use \\\\server\\share",
                "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="
            ])
        }
        event["process"]["parent"] = {
            "name": "explorer.exe"
        }

    if pattern["name"] == "Data Exfiltration":
        event["dns"] = {
            "question": {
                "name": f"{random.randbytes(16).hex()}.malicious-domain.com",
                "type": "TXT"
            }
        }
        event["file"] = {
            "size": random.randint(1000000, 100000000),
            "name": random.choice(["data.zip", "export.csv", "backup.tar.gz"])
        }

    return event

# Génération des événements
print(f"[+] Génération de {TARGET_SIZE_MB} MB d'événements...")
print(f"    Taille cible: {TARGET_SIZE_BYTES:,} bytes")
print()

total_bytes = 0
total_events = 0
batch_num = 1
batch_events = []

# Période de 30 jours
start_time = int((datetime.now() - timedelta(days=30)).timestamp())
end_time = int(datetime.now().timestamp())

try:
    while total_bytes < TARGET_SIZE_BYTES:
        # Timestamp aléatoire dans les 30 derniers jours
        timestamp = random.randint(start_time, end_time)

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

            print(f"    Batch {batch_num:04d}: {len(batch_events):,} événements, {batch_size:,} bytes (Total: {total_bytes/1024/1024:.1f} MB / {TARGET_SIZE_MB} MB)")

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

        print(f"    Batch {batch_num:04d}: {len(batch_events):,} événements, {batch_size:,} bytes (Total: {total_bytes/1024/1024:.1f} MB / {TARGET_SIZE_MB} MB)")

except Exception as e:
    print(f"\n[!] Erreur: {e}")
    import traceback
    traceback.print_exc()

finally:
    conn.close()

print()
print("="*80)
print("✅ GÉNÉRATION TERMINÉE")
print("="*80)
print(f"Total événements: {total_events:,}")
print(f"Total fichiers: {batch_num}")
print(f"Taille totale: {total_bytes/1024/1024:.2f} MB")
print(f"Fichiers: {OUTPUT_PREFIX}0001.json à {OUTPUT_PREFIX}{batch_num:04d}.json")
print()
