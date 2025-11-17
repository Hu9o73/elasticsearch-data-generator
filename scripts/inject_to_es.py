#!/usr/bin/env python3
"""
Script d'injection de données dans Elasticsearch via l'API Bulk
Compatible avec Elasticsearch 8.x
"""

import os
import requests
import json
import time
import glob
from dotenv import load_dotenv
import urllib3
urllib3.disable_warnings()

load_dotenv()

# Configuration Elasticsearch
ES_URL = os.getenv("ES_URL", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "3LYN_virPJ_TzasQ65qH")
ES_INDEX_PREFIX = os.getenv("ES_INDEX_PREFIX", "fusionai-security")

# Batch files
BATCH_PATTERN = os.getenv("BATCH_PATTERN", "/home/debian/events_es_batch_*.json")
BULK_SIZE = int(os.getenv("BULK_SIZE", "1000"))  # Nombre d'événements par requête bulk

print("="*80)
print("🚀 INJECTION DE DONNÉES DANS ELASTICSEARCH")
print("="*80)
print()

# Étape 1: Connexion à Elasticsearch
print("[1] Connexion à Elasticsearch...")
try:
    response = requests.get(
        f"{ES_URL}",
        auth=(ES_USER, ES_PASS),
        verify=False
    )

    if response.status_code == 200:
        cluster_info = response.json()
        print(f"    [✓] Connecté au cluster: {cluster_info.get('cluster_name', 'unknown')}")
        print(f"    [✓] Version: {cluster_info.get('version', {}).get('number', 'unknown')}")
    else:
        print(f"    [✗] Erreur de connexion: {response.status_code}")
        exit(1)
except Exception as e:
    print(f"    [✗] Erreur: {e}")
    exit(1)

print()

# Étape 2: Créer l'index avec mapping
print("[2] Création de l'index avec mapping...")

# Créer un index template pour tous les index fusionai-*
index_template = {
    "index_patterns": ["fusionai-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "30s"
        },
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {
                    "properties": {
                        "category": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "kind": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "outcome": {"type": "keyword"}
                    }
                },
                "source": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "integer"},
                        "bytes": {"type": "long"}
                    }
                },
                "destination": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "integer"},
                        "bytes": {"type": "long"}
                    }
                },
                "network": {
                    "properties": {
                        "protocol": {"type": "keyword"},
                        "bytes": {"type": "long"},
                        "direction": {"type": "keyword"}
                    }
                },
                "user": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "domain": {"type": "keyword"},
                        "department": {"type": "keyword"}
                    }
                },
                "host": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "risk_level": {"type": "keyword"}
                    }
                },
                "threat": {
                    "properties": {
                        "framework": {"type": "keyword"},
                        "technique": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "name": {"type": "text"}
                            }
                        },
                        "tactic": {
                            "properties": {
                                "name": {"type": "keyword"}
                            }
                        }
                    }
                },
                "security": {
                    "properties": {
                        "signature": {"type": "text"},
                        "category": {"type": "keyword"},
                        "severity": {"type": "keyword"}
                    }
                },
                "tags": {"type": "keyword"},
                "labels": {"type": "object"}
            }
        }
    }
}

try:
    response = requests.put(
        f"{ES_URL}/_index_template/fusionai-template",
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"},
        json=index_template,
        verify=False
    )

    if response.status_code in [200, 201]:
        print("    [✓] Template d'index créé")
    else:
        print(f"    [!] Template existe déjà ou erreur: {response.status_code}")
except Exception as e:
    print(f"    [✗] Erreur: {e}")

print()

# Étape 3: Lister les fichiers batch
print("[3] Chargement des fichiers batch...")
batch_files = sorted(glob.glob(BATCH_PATTERN))

if not batch_files:
    print(f"    [✗] Aucun fichier trouvé: {BATCH_PATTERN}")
    exit(1)

print(f"    [✓] {len(batch_files)} fichiers trouvés")
print()

# Étape 4: Injection via Bulk API
print("[4] Injection des événements...")
total_events = 0
total_bytes = 0
start_time = time.time()

# Créer l'index avec timestamp
index_name = f"{ES_INDEX_PREFIX}-{time.strftime('%Y.%m.%d')}"

for batch_file in batch_files:
    batch_num = batch_file.split("_")[-1].replace(".json", "")

    print(f"    Batch {batch_num}...")

    # Lire le fichier
    events = []
    with open(batch_file, 'r') as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    # Injection par chunks de BULK_SIZE
    for i in range(0, len(events), BULK_SIZE):
        chunk = events[i:i + BULK_SIZE]

        # Préparer le payload Bulk API
        bulk_data = ""
        for event in chunk:
            # Action line (index)
            action = json.dumps({"index": {"_index": index_name}})
            # Document line
            doc = json.dumps(event)
            bulk_data += action + "\n" + doc + "\n"

        # Injection via Bulk API
        try:
            response = requests.post(
                f"{ES_URL}/_bulk",
                auth=(ES_USER, ES_PASS),
                headers={"Content-Type": "application/x-ndjson"},
                data=bulk_data,
                verify=False,
                timeout=60
            )

            if response.status_code == 200:
                result = response.json()

                # Vérifier les erreurs
                if result.get("errors"):
                    error_count = sum(1 for item in result.get("items", [])
                                     if item.get("index", {}).get("error"))
                    print(f"        [!] {error_count} erreurs sur {len(chunk)} événements")
                else:
                    total_events += len(chunk)
                    total_bytes += len(bulk_data)

            else:
                print(f"        [✗] Erreur {response.status_code}: {response.text[:200]}")

        except Exception as e:
            print(f"        [✗] Erreur: {e}")

    print(f"        [✓] {len(events):,} événements traités (Total: {total_events:,})")

elapsed = time.time() - start_time

print()
print("="*80)
print("✅ INJECTION TERMINÉE")
print("="*80)
print(f"Index: {index_name}")
print(f"Total événements: {total_events:,}")
print(f"Total bytes: {total_bytes:,} ({total_bytes/1024/1024:.1f} MB)")
print(f"Temps: {elapsed:.1f}s")
print(f"Vitesse: {total_events/elapsed:.0f} événements/s")
print()
print("IMPORTANT: Vérifiez dans Elasticsearch avec:")
print(f"  curl -k -u {ES_USER}:PASS {ES_URL}/{index_name}/_count")
print(f"  curl -k -u {ES_USER}:PASS {ES_URL}/{index_name}/_search?size=5")
print()
