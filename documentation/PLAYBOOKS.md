# Attack Chain Playbooks

Correlated chains are built by `scripts/attack_chains/generator.py`, which selects entries from `PLAYBOOKS`. Each playbook emits multiple ECS-like events sharing user/asset/IP context and an `attack.id`, with realistic spacing between steps. Chains can stop early when enforcement blocks progress (`chain_stop_reason: blocked_mid_chain`).

- Playbooks live under `scripts/attack_chains/playbooks/`, one module per chain, aggregated via `playbooks/__init__.py`.

## Ratio controls
- `ATTACK_CHAIN_RATIO` raises/lowers how often a chain is emitted versus a single alert.
- `NOISE_RATIO` mixes in benign events (see `documentation/NOISE.md`). Both are clamped to `0..0.95` and scaled down together if their sum would starve baseline alerts.

## Scenario coverage (playbook -> highlights)
- `powershell_dropper_chain`: Outlook-spawned PowerShell with encoded payload, dropper + Run key, outbound PUT exfil attempt.
- `ssh_lateral_chain`: SSH brute force, allowed session, tar staging for later exfil.
- `ransomware_encryption_chain`: Macro to wscript, shadow copy wipe, encryption and ransom note.
- `sql_injection_exfil_chain`: Web SQLi probe, DB dump, HTTPS exfil attempt.
- `rdp_persistence_chain`: Credential reuse on RDP, scheduled task persistence, internal RDP pivot.
- `vpn_phishing_chain`: Foreign VPN login, hidden PowerShell, outbound credential theft.
- `kerberos_golden_ticket_chain`: Mimikatz dump, forged tickets, WMI remote execution.
- `linux_crypto_miner_chain`: Curl pipe to bash, miner drop, outbound mining pool traffic.
- `cloud_cli_abuse_chain`: AWS CLI configuration, EC2 inventory, S3 sync toward rogue bucket.
- `smb_data_wiper_chain`: PsExec over SMB, event log clearing, destructive wipe of finance backups.
- `cloud_key_abuse_chain`: AWS STS from new ASN, S3 listing, iam:PassRole attempt, S3 sync exfil, EC2 miner launch, Azure consent grant.
- `saas_account_takeover_chain`: MFA fatigue on Okta/Entra, unusual SaaS login, inbox rule creation, Graph bulk export, GDrive mass download.
- `insider_misuse_chain`: After-hours HR dump, personal cloud upload, USB copy, sudo failures then root-led archiving.
- `lateral_movement_variants_chain`: WMI/WinRM remote exec, PsExec service drop, RDP file move, SSH agent hijack with scp hop, Kerberoasting.
- `phishing_initial_access_chain`: Macro → mshta/wscript, ISO/LNK mount, HTML smuggling drop, signed LOLBin download/execution.
- `defense_evasion_chain`: EDR/AV tamper, AMSI bypass strings, Sysmon disable, timestomp, signed driver abuse.
- `c2_nuance_chain`: Domain-fronted TLS, DoH beacons, OneDrive/GDrive-style C2, jittered beaconing with user-agent rotation.
- `data_staging_exfil_chain`: 7z/tar staging, chunked pastebin uploads, DNS tunneling, SMB to rogue host, curl `--data-binary` to CDN-like endpoints.
- `ransomware_extended_chain`: Shadow copy deletion, backup share wipe, GPO recovery disable, encryption, ransom note with onion link.
- `supply_chain_dev_abuse_chain`: CI runner pulling unsigned script, npm/pip dependency confusion, GitHub PAT reuse from non-corp IP, secret scan hit on push.
