from .c2_nuance_chain import c2_nuance_chain
from .cloud_cli_abuse_chain import cloud_cli_abuse_chain
from .cloud_key_abuse_chain import cloud_key_abuse_chain
from .data_staging_exfil_chain import data_staging_exfil_chain
from .defense_evasion_chain import defense_evasion_chain
from .insider_misuse_chain import insider_misuse_chain
from .kerberos_golden_ticket_chain import kerberos_golden_ticket_chain
from .lateral_movement_variants_chain import lateral_movement_variants_chain
from .linux_crypto_miner_chain import linux_crypto_miner_chain
from .phishing_initial_access_chain import phishing_initial_access_chain
from .powershell_dropper_chain import powershell_dropper_chain
from .ransomware_encryption_chain import ransomware_encryption_chain
from .ransomware_extended_chain import ransomware_extended_chain
from .rdp_persistence_chain import rdp_persistence_chain
from .saas_account_takeover_chain import saas_account_takeover_chain
from .smb_data_wiper_chain import smb_data_wiper_chain
from .sql_injection_exfil_chain import sql_injection_exfil_chain
from .ssh_lateral_chain import ssh_lateral_chain
from .supply_chain_dev_abuse_chain import supply_chain_dev_abuse_chain
from .vpn_phishing_chain import vpn_phishing_chain

PLAYBOOKS = [
    powershell_dropper_chain,
    ssh_lateral_chain,
    ransomware_encryption_chain,
    sql_injection_exfil_chain,
    rdp_persistence_chain,
    vpn_phishing_chain,
    kerberos_golden_ticket_chain,
    linux_crypto_miner_chain,
    cloud_cli_abuse_chain,
    smb_data_wiper_chain,
    cloud_key_abuse_chain,
    saas_account_takeover_chain,
    insider_misuse_chain,
    lateral_movement_variants_chain,
    phishing_initial_access_chain,
    defense_evasion_chain,
    c2_nuance_chain,
    data_staging_exfil_chain,
    ransomware_extended_chain,
    supply_chain_dev_abuse_chain,
]

__all__ = [
    "PLAYBOOKS",
    "powershell_dropper_chain",
    "ssh_lateral_chain",
    "ransomware_encryption_chain",
    "sql_injection_exfil_chain",
    "rdp_persistence_chain",
    "vpn_phishing_chain",
    "kerberos_golden_ticket_chain",
    "linux_crypto_miner_chain",
    "cloud_cli_abuse_chain",
    "smb_data_wiper_chain",
    "cloud_key_abuse_chain",
    "saas_account_takeover_chain",
    "insider_misuse_chain",
    "lateral_movement_variants_chain",
    "phishing_initial_access_chain",
    "defense_evasion_chain",
    "c2_nuance_chain",
    "data_staging_exfil_chain",
    "ransomware_extended_chain",
    "supply_chain_dev_abuse_chain",
]
