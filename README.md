# Elasticsearch Data Generator

**Un générateur de données de sécurité réalistes pour Elasticsearch**

Ce projet permet de générer et d'injecter des événements de sécurité réalistes dans Elasticsearch pour tester des solutions SIEM, SOC, et d'analyse de sécurité comme FusionAI.

Adapté depuis [splunk-data-generator](https://github.com/philoo99999/splunk-data-generator) pour fonctionner avec Elasticsearch 8.x.

## 🎯 Caractéristiques

- ✅ Génération de 500 MB à 3+ GB de données d'attaques réalistes
- ✅ Support de multiples types d'attaques cyber (SQL Injection, XSS, Lateral Movement, Data Exfiltration, etc.)
- ✅ Mapping MITRE ATT&CK (techniques et tactiques)
- ✅ Format ECS (Elastic Common Schema) compatible
- ✅ Intégration avec Active Directory (utilisateurs) et CMDB (assets)
- ✅ Injection via Elasticsearch Bulk API
- ✅ Compatible avec Elasticsearch 8.x

## 🔐 Types d'Attaques Générées

| Attaque | Sévérité | Techniques MITRE | Description |
|---------|----------|------------------|-------------|
| **SQL Injection** | CRITICAL | T1190, T1189 | URLs malveillantes avec injections SQL réalistes |
| **Cross-Site Scripting (XSS)** | HIGH | T1189, T1203 | Scripts JavaScript injectés, Payloads XSS variés |
| **Lateral Movement** | CRITICAL | T1021, T1550 | SMB, RDP, Pass-the-Hash, mouvements réseau suspects |
| **Data Exfiltration** | CRITICAL | T1048, T1041 | DNS exfiltration, transferts FTP/HTTPS massifs |
| **Reconnaissance** | MEDIUM | T1046, T1087 | Port scans, énumération réseau et LDAP |

## 📋 Prérequis

- Python 3.6+
- Elasticsearch 8.x en cours d'exécution
- Bibliothèques Python: `requests`, `urllib3`, `elasticsearch`

## 📂 Structure du Projet

```
elasticsearch-data-generator/
├── scripts/
│   ├── generate_events.py       # Génère les événements
│   ├── inject_to_es.py          # Injecte dans Elasticsearch
│   └── verify_es.py             # Vérifie les données injectées
├── requirements.txt
├── .gitignore
└── README.md
```

## 🚀 Installation

1. **Clonez ce repository:**
```bash
git clone https://github.com/philoo99999/elasticsearch-data-generator.git
cd elasticsearch-data-generator
```

2. **Installez les dépendances:**
```bash
pip install -r requirements.txt
```

3. **Préparez vos données de référence:**
   - `DATABASE_FusionAI.db` - Base de données SQLite avec alertes et IPs
   - `ad_users.csv` (optionnel) - Liste des utilisateurs Active Directory
   - `cmdb_assets.csv` (optionnel) - Liste des assets de votre CMDB

## 💻 Utilisation

### 1. Démarrer Elasticsearch

Assurez-vous qu'Elasticsearch est en cours d'exécution:

```bash
sudo systemctl status elasticsearch
```

### 2. Générer les Données

Générez 500 MB de données d'événements de sécurité:

```bash
python3 scripts/generate_events.py
```

Le script génère:
- 700,000+ événements
- 7 fichiers batch (~71 MB chacun)
- Événements répartis sur 30 jours
- Mix réaliste d'attaques avec mapping MITRE ATT&CK

**Personnalisation:**
Modifiez `TARGET_SIZE_MB` dans le script pour générer plus ou moins de données.

### 3. Injecter dans Elasticsearch

**Configuration:**
Éditez `scripts/inject_to_es.py` avec vos credentials Elasticsearch:

```python
ES_URL = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "votre_mot_de_passe"
```

**Injection:**
```bash
python3 scripts/inject_to_es.py
```

Le script:
- Se connecte à Elasticsearch
- Crée un index template avec mapping ECS
- Injecte les événements via Bulk API
- Affiche la progression en temps réel
- Temps estimé: 5-10 minutes pour 500 MB

### 4. Vérifier l'Injection

```bash
python3 scripts/verify_es.py
```

Ou directement avec curl:

```bash
# Compter les événements
curl -k -u elastic:PASSWORD https://localhost:9200/fusionai-*/_count

# Voir les index
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/indices/fusionai-*?v

# Rechercher
curl -k -u elastic:PASSWORD https://localhost:9200/fusionai-*/_search?size=5
```

## 📊 Exemples de Requêtes Elasticsearch

### Top 10 des IPs sources
```json
GET /fusionai-*/_search
{
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
```

### Attaques par Sévérité
```json
GET /fusionai-*/_search
{
  "size": 0,
  "aggs": {
    "by_severity": {
      "terms": {
        "field": "event.severity"
      }
    }
  }
}
```

### Timeline des Attaques
```json
GET /fusionai-*/_search
{
  "size": 0,
  "aggs": {
    "timeline": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "day"
      },
      "aggs": {
        "by_category": {
          "terms": {
            "field": "security.category"
          }
        }
      }
    }
  }
}
```

### Techniques MITRE ATT&CK
```json
GET /fusionai-*/_search
{
  "size": 0,
  "aggs": {
    "mitre_techniques": {
      "terms": {
        "field": "threat.technique.id",
        "size": 20
      },
      "aggs": {
        "tactics": {
          "terms": {
            "field": "threat.tactic.name"
          }
        }
      }
    }
  }
}
```

### Événements d'une IP Spécifique
```json
GET /fusionai-*/_search
{
  "query": {
    "term": {
      "source.ip": "10.14.45.103"
    }
  }
}
```

## 🔧 Configuration

### Format ECS (Elastic Common Schema)

Les événements générés suivent le format ECS pour une compatibilité maximale avec l'écosystème Elastic:

```json
{
  "@timestamp": "2025-11-16T10:30:00.000Z",
  "event": {
    "category": "security",
    "severity": "critical",
    "kind": "alert"
  },
  "source": {
    "ip": "192.168.1.100",
    "port": 54321
  },
  "destination": {
    "ip": "10.0.1.50",
    "port": 443
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {
      "id": "T1190",
      "name": "SQL Injection"
    }
  }
}
```

### Données de Référence

#### Format ad_users.csv (optionnel)
```csv
Username,Department,Display_Name
jsmith,IT,John Smith
mdoe,Finance,Mary Doe
```

#### Format cmdb_assets.csv (optionnel)
```csv
Hostname,Asset_Type,Criticality,Location
WKS-001,Workstation,Medium,Building A
SRV-001,Server,Critical,DataCenter
```

Si ces fichiers ne sont pas fournis, le générateur crée des données par défaut.

## 🔍 Dépannage

### Erreur: "Connection refused"
Elasticsearch n'est pas démarré:
```bash
sudo systemctl start elasticsearch
sudo systemctl status elasticsearch
```

### Erreur: "Authentication failed"
Vérifiez vos credentials dans `inject_to_es.py`:
```bash
# Réinitialiser le mot de passe
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

### Erreur: "Index creation failed"
Vérifiez que vous avez les droits suffisants et que l'index n'existe pas déjà:
```bash
curl -k -u elastic:PASSWORD -X DELETE https://localhost:9200/fusionai-*
```

## 🎨 Visualisation avec Kibana

1. **Installer Kibana** (optionnel):
```bash
sudo apt-get install kibana
sudo systemctl start kibana
```

2. **Accéder à Kibana**: http://localhost:5601

3. **Créer un Data View**:
   - Stack Management → Data Views
   - Create data view: `fusionai-*`
   - Timestamp field: `@timestamp`

4. **Créer des visualisations**:
   - Dashboard → Create visualization
   - Utilisez les champs ECS pour créer des graphiques

## 📈 Performance

| Métrique | Valeur |
|----------|--------|
| Taille des événements | ~800 bytes/événement |
| Vitesse de génération | ~50,000 événements/s |
| Vitesse d'injection | ~5,000-10,000 événements/s |
| Temps pour 500 MB | ~5-10 minutes |

## 🔒 Sécurité

- ⚠️ Ne partagez JAMAIS vos mots de passe Elasticsearch publiquement
- ⚠️ Les données générées sont pour environnements de test uniquement
- ⚠️ Utilisez HTTPS et des mots de passe forts en production

## 🤝 Contribuer

Les contributions sont les bienvenues ! N'hésitez pas à:
- Reporter des bugs via les Issues
- Proposer des améliorations via des Pull Requests
- Ajouter de nouveaux types d'attaques
- Améliorer la documentation

## 📄 Licence

MIT License - Voir le fichier LICENSE pour plus de détails

## 👤 Auteur

Adapté pour Elasticsearch depuis [splunk-data-generator](https://github.com/philoo99999/splunk-data-generator)

Projet créé pour tester et développer des solutions SIEM/SOC comme FusionAI.

## 🔗 Liens Utiles

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Kibana User Guide](https://www.elastic.co/guide/en/kibana/current/index.html)

## 📝 Changelog

### v1.0.0 (2025-11-16)
- ✅ Génération initiale de 500 MB de données
- ✅ Support des 5 types d'attaques principaux
- ✅ Format ECS compatible
- ✅ Injection via Bulk API
- ✅ Scripts de vérification
- ✅ Documentation complète

---

**Note:** Ce projet est conçu pour des environnements de test et de développement. N'utilisez pas en production sans validation appropriée.
