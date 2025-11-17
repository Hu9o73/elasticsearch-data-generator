#!/usr/bin/env python3
"""
Script de vérification des données injectées dans Elasticsearch
"""

import os
import requests
import json
from dotenv import load_dotenv
import urllib3
urllib3.disable_warnings()

load_dotenv()

# Configuration Elasticsearch
ES_URL = os.getenv("ES_URL", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "3LYN_virPJ_TzasQ65qH")
INDEX_PATTERN = os.getenv("INDEX_PATTERN", "fusionai-*")

print("="*80)
print("🔍 VÉRIFICATION DES DONNÉES ELASTICSEARCH")
print("="*80)
print()

# 1. Connexion
print("[1] Connexion à Elasticsearch...")
try:
    response = requests.get(
        f"{ES_URL}",
        auth=(ES_USER, ES_PASS),
        verify=False
    )

    if response.status_code == 200:
        cluster_info = response.json()
        print(f"    [✓] Cluster: {cluster_info.get('cluster_name')}")
        print(f"    [✓] Version: {cluster_info['version']['number']}")
    else:
        print(f"    [✗] Erreur: {response.status_code}")
        exit(1)
except Exception as e:
    print(f"    [✗] Erreur: {e}")
    exit(1)

print()

# 2. Lister les index
print("[2] Index disponibles...")
try:
    response = requests.get(
        f"{ES_URL}/_cat/indices/{INDEX_PATTERN}?v&h=index,docs.count,store.size&s=index",
        auth=(ES_USER, ES_PASS),
        verify=False
    )

    if response.status_code == 200:
        print(response.text)
    else:
        print(f"    [✗] Erreur: {response.status_code}")
except Exception as e:
    print(f"    [✗] Erreur: {e}")

print()

# 3. Compter les événements
print("[3] Nombre total d'événements...")
try:
    response = requests.get(
        f"{ES_URL}/{INDEX_PATTERN}/_count",
        auth=(ES_USER, ES_PASS),
        verify=False
    )

    if response.status_code == 200:
        result = response.json()
        count = result.get('count', 0)
        print(f"    [✓] Total: {count:,} événements")
    else:
        print(f"    [✗] Erreur: {response.status_code}")
except Exception as e:
    print(f"    [✗] Erreur: {e}")

print()

# 4. Statistiques par sévérité
print("[4] Répartition par sévérité...")
try:
    query = {
        "size": 0,
        "aggs": {
            "by_severity": {
                "terms": {
                    "field": "event.severity",
                    "size": 10
                }
            }
        }
    }

    response = requests.post(
        f"{ES_URL}/{INDEX_PATTERN}/_search",
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False
    )

    if response.status_code == 200:
        result = response.json()
        buckets = result.get('aggregations', {}).get('by_severity', {}).get('buckets', [])
        for bucket in buckets:
            severity = bucket['key']
            count = bucket['doc_count']
            print(f"    {severity.upper():12s}: {count:,}")
    else:
        print(f"    [✗] Erreur: {response.status_code}")
except Exception as e:
    print(f"    [✗] Erreur: {e}")

print()

# 5. Statistiques par catégorie d'attaque
print("[5] Répartition par catégorie d'attaque...")
try:
    query = {
        "size": 0,
        "aggs": {
            "by_category": {
                "terms": {
                    "field": "security.category",
                    "size": 10
                }
            }
        }
    }

    response = requests.post(
        f"{ES_URL}/{INDEX_PATTERN}/_search",
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False
    )

    if response.status_code == 200:
        result = response.json()
        buckets = result.get('aggregations', {}).get('by_category', {}).get('buckets', [])
        for bucket in buckets:
            category = bucket['key']
            count = bucket['doc_count']
            print(f"    {category:25s}: {count:,}")
    else:
        print(f"    [✗] Erreur: {response.status_code}")
except Exception as e:
    print(f"    [✗] Erreur: {e}")

print()

# 6. Top 10 source IPs
print("[6] Top 10 IPs sources...")
try:
    query = {
        "size": 0,
        "aggs": {
            "top_sources": {
                "terms": {
                    "field": "source.ip",
                    "size": 10
                }
            }
        }
    }

    response = requests.post(
        f"{ES_URL}/{INDEX_PATTERN}/_search",
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False
    )

    if response.status_code == 200:
        result = response.json()
        buckets = result.get('aggregations', {}).get('top_sources', {}).get('buckets', [])
        for i, bucket in enumerate(buckets, 1):
            ip = bucket['key']
            count = bucket['doc_count']
            print(f"    {i:2d}. {ip:15s}: {count:,} événements")
    else:
        print(f"    [✗] Erreur: {response.status_code}")
except Exception as e:
    print(f"    [✗] Erreur: {e}")

print()

# 7. Techniques MITRE ATT&CK
print("[7] Techniques MITRE ATT&CK...")
try:
    query = {
        "size": 0,
        "aggs": {
            "mitre_techniques": {
                "terms": {
                    "field": "threat.technique.id",
                    "size": 10
                }
            }
        }
    }

    response = requests.post(
        f"{ES_URL}/{INDEX_PATTERN}/_search",
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False
    )

    if response.status_code == 200:
        result = response.json()
        buckets = result.get('aggregations', {}).get('mitre_techniques', {}).get('buckets', [])
        for bucket in buckets:
            technique = bucket['key']
            count = bucket['doc_count']
            print(f"    {technique:10s}: {count:,}")
    else:
        print(f"    [✗] Erreur: {response.status_code}")
except Exception as e:
    print(f"    [✗] Erreur: {e}")

print()

# 8. Exemple d'événements
print("[8] Exemples d'événements (3 premiers)...")
try:
    query = {
        "size": 3,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "event.severity", "security.category", "source.ip", "destination.ip"]
    }

    response = requests.post(
        f"{ES_URL}/{INDEX_PATTERN}/_search",
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False
    )

    if response.status_code == 200:
        result = response.json()
        hits = result.get('hits', {}).get('hits', [])
        for i, hit in enumerate(hits, 1):
            source = hit['_source']
            print(f"\n    Événement {i}:")
            print(f"      Timestamp: {source.get('@timestamp')}")
            print(f"      Sévérité:  {source.get('event', {}).get('severity')}")
            print(f"      Catégorie: {source.get('security', {}).get('category')}")
            print(f"      Source:    {source.get('source', {}).get('ip')}")
            print(f"      Dest:      {source.get('destination', {}).get('ip')}")
    else:
        print(f"    [✗] Erreur: {response.status_code}")
except Exception as e:
    print(f"    [✗] Erreur: {e}")

print()
print("="*80)
print("✅ VÉRIFICATION TERMINÉE")
print("="*80)
print()
