# Why the Generated Data Feels Real

This generator is built to mirror how security teams see data in a SIEM/EDR pipeline, not just to emit random alerts.

- Grounded distributions: IPs, ports, protocols, severities, signatures, and categories are drawn from the SQLite alerts DB when available; AD users and CMDB assets give real-looking names, owners, locations, OS versions, and risk levels.
- Correlated attack chains: Playbooks emit multi-step, time-correlated events with shared users/assets/IPs plus `attack.id`/`attack.stage`/`attack.sequence`, matching real investigations where lateral movement or staged exfiltration creates clusters.
- MITRE mapping: Each category maps to MITRE ATT&CK tactics/techniques so dashboards and detections align with common frameworks.
- Seasonality and noise: Optional seasonality biases benign events into business hours/maintenance windows; noise events (vuln scans, backups, admin logons) keep baselines realistic.
- OS-native telemetry: Windows hosts carry Sysmon-style fields (`winlog`, `event.code`, event IDs like 1/3/11/13/22); Linux hosts use auditd/syslog-style blocks (`auditd`, `log`). Category heuristics pick plausible processes (e.g., sshd for SSH lateral, sudo for privilege actions).
- Deepen variety: Powershell categories get encoded `-enc` commands, DGA categories get random DNS lookups, exfil chains include file/url detail, and randomness can be seeded (`SEED`) for reproducibility.

# How to read the generated logs
- Schema backbone: Alerts follow an ECS-like shape (`event`, `source`, `destination`, `network`, `user`, `host`, `threat`, `rule`, `tags`, `labels`) so downstream SIEM/ES parsers work without custom mappings.
- Host/user coherence: `destination.ip` matches a CMDB asset (`host.ip`, `host.hostname`, `host.os`), and `user` comes from AD-like data, preventing mixed identities that break investigations.
- Network realism: Ports/protocols use real distributions (when DB is present), bytes are in plausible ranges, and `network.direction` reflects the scenario (inbound, outbound, internal).
- Outcome semantics: `event.action` and `event.outcome` stay consistent (e.g., blocked -> failure) while still allowing logged/allowed variants to model noisy-but-allowed behaviors.
- Threat context: `threat.tactic/technique` come from category-to-MITRE mapping, giving SOC views the same structure as real alert feeds.
- Noise vs signal: Background events mark `fusionai.noise=true` with benign scenarios (scans, backups, logons) to keep baselines realistic; attack chains share `attack.id`/`stage`/`sequence` for correlation.
- Platform cues:
  - Windows: `winlog` + `event.code` mirror Sysmon (1 process creation, 3 network, 11 file, 13 registry, 22 DNS). Includes process GUID/IDs, images, command lines, and endpoints.
  - Linux: `auditd` + `log` mimic audit/syslog, with `auditd.type` (USER_LOGIN/USER_CMD/SYSCALL/CRED_ACQ), TTY, exe, addr, and success flags, plus syslog facility/severity hints.
- Tunable realism: Seasonality (`NOISE_SEASONALITY`), hourly weights, and ratios (`ATTACK_CHAIN_RATIO`, `NOISE_RATIO`) let you bias toward daytime ops, maintenance windows, or bursty attacks; `SEED` locks runs for reproducible testing.

# Example Event (Windows, Lateral Movement)

```json
{
  "@timestamp": "2024-08-12T10:21:44",
  "event": {
    "category": "security",
    "type": "alert",
    "kind": "alert",
    "severity": "medium",
    "action": "allowed",
    "outcome": "success",
    "module": "psexec_lateral",
    "dataset": "fusionai.alerts",
    "code": "3",
    "provider": "Microsoft-Windows-Sysmon"
  },
  "source": {"ip": "198.51.100.42", "port": 52244, "bytes": 18422},
  "destination": {"ip": "10.0.4.9", "port": 445, "bytes": 90331},
  "network": {"protocol": "tcp", "bytes": 108753, "direction": "internal"},
  "user": {
    "name": "alice",
    "domain": "fusionai.local",
    "email": "alice@fusionai.local",
    "department": "IT",
    "full_name": "Alice Example"
  },
  "host": {
    "name": "WKS-002",
    "hostname": "WKS-002",
    "type": "Workstation",
    "ip": ["10.0.4.9"],
    "os": {"name": "Windows 10 Pro", "platform": "windows"},
    "risk": {"static_level": "medium"}
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {"id": ["T1021.002"], "name": ["psexec_lateral"]},
    "tactic": {"name": ["Lateral Movement"]}
  },
  "rule": {"name": "PSEXEC Service Creation", "category": "psexec_lateral", "id": "4821"},
  "fusionai": {
    "signature": "PSEXEC Service Creation",
    "category": "psexec_lateral",
    "severity": "2",
    "asset_owner": "Martine Robert",
    "asset_location": "Office",
    "asset_department": "IT"
  },
  "winlog": {
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider_name": "Microsoft-Windows-Sysmon",
    "computer_name": "WKS-002",
    "event_id": 3,
    "record_id": 742331,
    "opcode": "Info",
    "process": {"pid": 8842, "thread_id": 3011},
    "event_data": {
      "UtcTime": "2024-08-12T10:21:44Z",
      "Image": "C:\\\\Windows\\\\System32\\\\psexesvc.exe",
      "User": "fusionai.local\\\\alice",
      "Protocol": "TCP",
      "SourceIp": "198.51.100.42",
      "SourcePort": 52244,
      "DestinationIp": "10.0.4.9",
      "DestinationPort": 445,
      "Initiated": "true",
      "ProcessGuid": "{4a2f1d0a8f1a4ce3bd2c6a9f8c5d7f21}",
      "ProcessId": 8842
    }
  },
  "tags": ["psexec_lateral", "medium", "fusionai", "office"],
  "labels": {"env": "production", "source": "fusionai_generator", "data_source": "real_fusion_ai"}
}
```

**What makes this realistic**
- Asset and user coherence: Destination IP/hostname/OS align with a CMDB asset; user/domain/email line up with AD-like data, keeping investigations consistent.
- MITRE + rule context: Category drives tactic/technique mapping and signature naming, so SOC views and detections match common playbooks.
- OS-native telemetry: Sysmon `event_id` 3 with `winlog.event_data` mirrors a real Sysmon network-connection record, including process GUID/IDs and TCP endpoints.
- Lateral flavor: Port 445 and `psexec_lateral` module signal SMB-based pivoting; internal direction matches a workstation-to-workstation move.
- Variability with realism: Bytes/ports/timestamps are randomized within plausible ranges; seeding (`SEED`) keeps runs reproducible for testing.
