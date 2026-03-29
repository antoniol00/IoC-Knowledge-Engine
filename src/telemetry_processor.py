"""
Telemetry Processor module.

Parses simulated telemetry data (network traces, malware classifications,
honeypot interactions, IoCs) and converts them into natural-language
summaries suitable for LLM consumption.
"""

import json
import os
from dataclasses import dataclass, field


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
TELEMETRY_PATH = os.path.join(DATA_DIR, "simulated_telemetry.json")


@dataclass
class ProcessedScenario:
    """Structured representation of a processed telemetry scenario."""

    scenario_id: str
    name: str
    severity: str
    description: str
    natural_language_summary: str
    iocs: dict = field(default_factory=dict)
    malware_info: dict = field(default_factory=dict)
    network_summary: str = ""
    honeypot_summary: str = ""
    raw_data: dict = field(default_factory=dict)


class TelemetryProcessor:

    def __init__(self, telemetry_path: str = None):
        """
        Initialize the telemetry processor.

        Args:
            telemetry_path: Path to simulated_telemetry.json. Defaults to
                            the bundled data file.
        """
        self.telemetry_path = telemetry_path or TELEMETRY_PATH
        self.raw_scenarios = []
        self._load_telemetry()

    def _load_telemetry(self):
        """Load raw telemetry data from JSON."""
        print("[*] Loading simulated telemetry data...")
        with open(self.telemetry_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.raw_scenarios = data.get("scenarios", [])
        print(f"    Loaded {len(self.raw_scenarios)} attack scenarios.")

    def process_all_scenarios(self) -> list[ProcessedScenario]:
        """
        Process all telemetry scenarios into structured summaries.

        Returns:
            List of ProcessedScenario objects.
        """
        processed = []
        for scenario in self.raw_scenarios:
            processed.append(self._process_scenario(scenario))
        return processed

    def process_scenario_by_id(self, scenario_id: str) -> ProcessedScenario | None:
        """
        Process a single scenario by its ID.

        Args:
            scenario_id: e.g., 'SC-001'

        Returns:
            ProcessedScenario or None if not found.
        """
        for scenario in self.raw_scenarios:
            if scenario["scenario_id"] == scenario_id:
                return self._process_scenario(scenario)
        return None

    def _process_scenario(self, scenario: dict) -> ProcessedScenario:
        network_summary = self._summarize_network_traces(
            scenario.get("network_traces", [])
        )
        honeypot_summary = self._summarize_honeypot_interactions(
            scenario.get("honeypot_interactions", [])
        )
        malware_summary = self._summarize_malware_classification(
            scenario.get("malware_classification", {})
        )
        ioc_summary = self._summarize_iocs(scenario.get("iocs", {}))

        # Build the full natural-language summary for LLM consumption
        nl_summary = self._build_full_summary(
            scenario, network_summary, honeypot_summary, malware_summary, ioc_summary
        )

        return ProcessedScenario(
            scenario_id=scenario["scenario_id"],
            name=scenario["name"],
            severity=scenario.get("severity", "UNKNOWN"),
            description=scenario.get("description", ""),
            natural_language_summary=nl_summary,
            iocs=scenario.get("iocs", {}),
            malware_info=scenario.get("malware_classification", {}),
            network_summary=network_summary,
            honeypot_summary=honeypot_summary,
            raw_data=scenario,
        )

    def _summarize_network_traces(self, traces: list[dict]) -> str:
        if not traces:
            return "No network traces available."

        lines = []
        for t in traces:
            direction = t.get("direction", "unknown")
            lines.append(
                f"  - [{t.get('timestamp', 'N/A')}] {t.get('protocol', '?')} "
                f"{t.get('src_ip', '?')}:{t.get('src_port', '?')} -> "
                f"{t.get('dst_ip', '?')}:{t.get('dst_port', '?')} "
                f"({direction}, {t.get('bytes_transferred', 0)} bytes) "
                f"| {t.get('payload_indicator', 'N/A')}"
            )
        return "Network activity observed:\n" + "\n".join(lines)

    def _summarize_honeypot_interactions(self, interactions: list[dict]) -> str:
        """Convert honeypot interactions into a readable summary."""
        if not interactions:
            return "No honeypot interactions recorded."

        lines = []
        for hp in interactions:
            commands = ", ".join(hp.get("commands_observed", []))
            lines.append(
                f"  - [{hp.get('timestamp', 'N/A')}] {hp.get('honeypot_type', '?')}: "
                f"{hp.get('interaction', 'N/A')}. Commands: {commands}"
            )
        return "Honeypot interactions:\n" + "\n".join(lines)

    def _summarize_malware_classification(self, classification: dict) -> str:
        """Convert malware classification into a readable summary."""
        if not classification:
            return "No malware classification available."

        behaviors = "\n".join(
            f"    * {b}" for b in classification.get("behavioral_indicators", [])
        )
        detection_names = ", ".join(classification.get("detection_names", []))
        hashes = classification.get("hashes", {})

        return (
            f"Malware Classification:\n"
            f"  Family: {classification.get('family', 'Unknown')}\n"
            f"  Type: {classification.get('type', 'Unknown')}\n"
            f"  File Type: {classification.get('file_type', 'Unknown')}\n"
            f"  Size: {classification.get('file_size_bytes', 0)} bytes\n"
            f"  SHA256: {hashes.get('sha256', 'N/A')}\n"
            f"  MD5: {hashes.get('md5', 'N/A')}\n"
            f"  Detection Names: {detection_names}\n"
            f"  Packer: {classification.get('packer', 'None')}\n"
            f"  Behavioral Indicators:\n{behaviors}"
        )

    def _summarize_iocs(self, iocs: dict) -> str:
        """Convert IoC dictionary into a readable summary."""
        if not iocs:
            return "No indicators of compromise available."

        lines = ["Indicators of Compromise (IoCs):"]

        if iocs.get("ip_addresses"):
            lines.append(f"  IP Addresses: {', '.join(iocs['ip_addresses'])}")
        if iocs.get("domains"):
            lines.append(f"  Domains: {', '.join(iocs['domains'])}")
        if iocs.get("urls"):
            lines.append(f"  URLs: {', '.join(iocs['urls'])}")
        if iocs.get("file_hashes"):
            lines.append(f"  File Hashes: {', '.join(iocs['file_hashes'])}")
        if iocs.get("email_addresses"):
            lines.append(f"  Email Addresses: {', '.join(iocs['email_addresses'])}")
        if iocs.get("registry_keys"):
            lines.append(f"  Registry Keys: {', '.join(iocs['registry_keys'])}")
        if iocs.get("malicious_packages"):
            lines.append(
                f"  Malicious Packages: {', '.join(iocs['malicious_packages'])}"
            )
        if iocs.get("mining_wallet"):
            lines.append(f"  Mining Wallet: {iocs['mining_wallet']}")
        if iocs.get("dns_tunneling_domains"):
            lines.append(
                f"  DNS Tunneling Domains: {', '.join(iocs['dns_tunneling_domains'])}"
            )

        return "\n".join(lines)

    def _build_full_summary(
        self,
        scenario: dict,
        network_summary: str,
        honeypot_summary: str,
        malware_summary: str,
        ioc_summary: str,
    ) -> str:
        """Assemble the complete natural-language summary for LLM analysis."""
        return (
            f"=== TELEMETRY REPORT: {scenario['name']} ===\n"
            f"Scenario ID: {scenario['scenario_id']}\n"
            f"Severity: {scenario.get('severity', 'UNKNOWN')}\n"
            f"Time Window: {scenario.get('timestamp_start', 'N/A')} to "
            f"{scenario.get('timestamp_end', 'N/A')}\n"
            f"Description: {scenario.get('description', 'N/A')}\n\n"
            f"{network_summary}\n\n"
            f"{malware_summary}\n\n"
            f"{honeypot_summary}\n\n"
            f"{ioc_summary}\n"
        )
