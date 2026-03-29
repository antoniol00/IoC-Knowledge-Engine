"""
Demo Scenarios module.

Provides pre-built scenario descriptions and expected output templates
to demonstrate the Knowledge Generation Engine capabilities.
"""


SCENARIO_INFO = {
    "SC-001": {
        "name": "Emotet Phishing Campaign",
        "short_description": (
            "Phishing email with macro-enabled document delivers Emotet "
            "banking trojan via PowerShell dropper."
        ),
        "expected_tactics": [
            "Initial Access",
            "Execution",
            "Persistence",
            "Command and Control",
            "Defense Evasion",
        ],
        "expected_techniques": [
            "T1566 - Phishing",
            "T1059.001 - PowerShell",
            "T1204 - User Execution",
            "T1547 - Boot or Logon Autostart Execution",
            "T1055 - Process Injection",
            "T1071 - Application Layer Protocol",
            "T1027 - Obfuscated Files or Information",
        ],
        "risk_level": "HIGH",
        "attack_group_similarity": "TA542 (Mummy Spider)",
    },
    "SC-002": {
        "name": "LockBit Ransomware Attack",
        "short_description": (
            "RDP brute force → lateral movement via SMB → data exfiltration "
            "→ LockBit 3.0 ransomware deployment."
        ),
        "expected_tactics": [
            "Initial Access",
            "Credential Access",
            "Lateral Movement",
            "Exfiltration",
            "Impact",
        ],
        "expected_techniques": [
            "T1110 - Brute Force",
            "T1021 - Remote Services (RDP)",
            "T1570 - Lateral Tool Transfer",
            "T1486 - Data Encrypted for Impact",
            "T1490 - Inhibit System Recovery",
            "T1041 - Exfiltration Over C2 Channel",
        ],
        "risk_level": "CRITICAL",
        "attack_group_similarity": "LockBit RaaS Affiliates",
    },
    "SC-003": {
        "name": "APT-Style Data Exfiltration",
        "short_description": (
            "Spearphishing PDF → DLL sideloading RAT → reconnaissance "
            "→ DNS tunneling exfiltration."
        ),
        "expected_tactics": [
            "Initial Access",
            "Execution",
            "Persistence",
            "Discovery",
            "Collection",
            "Exfiltration",
            "Command and Control",
            "Defense Evasion",
        ],
        "expected_techniques": [
            "T1566 - Phishing (Spearphishing Attachment)",
            "T1574 - Hijack Execution Flow (DLL Sideloading)",
            "T1053 - Scheduled Task/Job",
            "T1082 - System Information Discovery",
            "T1083 - File and Directory Discovery",
            "T1560 - Archive Collected Data",
            "T1048 - Exfiltration Over Alternative Protocol",
            "T1071.004 - Application Layer Protocol: DNS",
        ],
        "risk_level": "CRITICAL",
        "attack_group_similarity": "APT29 / Cozy Bear pattern",
    },
    "SC-004": {
        "name": "Cryptominer Deployment via Web Exploit",
        "short_description": (
            "Web server exploitation → XMRig miner deployment → cron "
            "persistence → internal network scanning."
        ),
        "expected_tactics": [
            "Initial Access",
            "Execution",
            "Persistence",
            "Impact",
            "Defense Evasion",
        ],
        "expected_techniques": [
            "T1190 - Exploit Public-Facing Application",
            "T1059 - Command and Scripting Interpreter",
            "T1053.003 - Scheduled Task/Job: Cron",
            "T1496 - Resource Hijacking",
            "T1036 - Masquerading",
            "T1105 - Ingress Tool Transfer",
        ],
        "risk_level": "MEDIUM",
        "attack_group_similarity": "TeamTNT / Generic Cryptojacking",
    },
    "SC-005": {
        "name": "Supply Chain Compromise via Trojanized Package",
        "short_description": (
            "Typosquatted PyPI package → reverse shell → credential "
            "harvesting → source code exfiltration."
        ),
        "expected_tactics": [
            "Initial Access",
            "Execution",
            "Credential Access",
            "Collection",
            "Exfiltration",
            "Lateral Movement",
        ],
        "expected_techniques": [
            "T1195 - Supply Chain Compromise",
            "T1059.006 - Python",
            "T1560 - Archive Collected Data",
            "T1041 - Exfiltration Over C2 Channel",
            "T1021.004 - Remote Services: SSH",
            "T1573 - Encrypted Channel",
        ],
        "risk_level": "HIGH",
        "attack_group_similarity": "Lazarus Group supply chain pattern",
    },
}


def get_scenario_ids() -> list[str]:
    """Return all available scenario IDs."""
    return list(SCENARIO_INFO.keys())


def get_scenario_info(scenario_id: str) -> dict | None:
    """Get metadata for a specific scenario."""
    return SCENARIO_INFO.get(scenario_id)


def print_scenario_menu():
    """Print a menu of available scenarios."""
    print("\n  Available Attack Scenarios:")
    print("  " + "─" * 50)
    for sid, info in SCENARIO_INFO.items():
        idx = sid.split("-")[1]
        print(f"  [{idx}] {info['name']}")
        print(f"       {info['short_description']}")
        print(f"       Risk: {info['risk_level']}")
        print()
