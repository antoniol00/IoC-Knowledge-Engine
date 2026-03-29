#!/usr/bin/env python3
import argparse
import json
import sys
import textwrap

from src.knowledge_engine import KnowledgeGenerationEngine
from src.demo_scenarios import (
    get_scenario_ids,
    get_scenario_info,
    print_scenario_menu,
)


def print_report(report: dict):
    """Pretty-print a knowledge report to the console."""
    meta = report["report_metadata"]
    threat = report["threat_assessment"]
    mitre = report["mitre_attck_mapping"]
    iocs = report["indicators_of_compromise"]

    print("\n" + "=" * 70)
    print(f"  KNOWLEDGE REPORT: {meta['scenario_name']}")
    print(f"  Scenario: {meta['scenario_id']}  |  Generated: {meta['generated_at']}")
    print(f"  Model: {meta['model_used']}")
    print("=" * 70)

    print("\n[ THREAT ASSESSMENT ]")
    print(f"│  Severity:        {threat['severity']}")
    print(f"│  Malware Family:  {threat['malware_family']}")
    print(f"│  Malware Type:    {threat['malware_type']}")
    print(f"│  Description:     {_wrap(threat['description'], 55)}")
    print("└────────────────────────────────────────────────────────────────┘")

    print("\n[ MITRE ATT&CK MAPPING ]")
    print(f"  Tactics Covered: {', '.join(mitre['tactic_coverage'])}")
    print("│")
    print("│  Mapped Techniques:")
    for ttp in mitre["mapped_ttps"]:
        print(
            f"│    ▸ {ttp['technique_id']}: {ttp['technique_name']} "
            f"[{ttp['tactic']}]"
        )

    # Add expected techniques from demo_scenarios for comparison
    scenario_info = get_scenario_info(meta["scenario_id"])
    if scenario_info:
        print("│")
        print("│  Expected Techniques (ground truth):")
        for t in scenario_info["expected_techniques"]:
            print(f"│    ◦ {t}")
        print(f"│")
        print(
            f"│  Attack Group Similarity: "
            f"{scenario_info.get('attack_group_similarity', 'N/A')}"
        )
    print("└────────────────────────────────────────────────────────────────┘")

    print("\n[ INDICATORS OF COMPROMISE ]")
    if iocs.get("ip_addresses"):
        print(f"│  IPs:      {', '.join(iocs['ip_addresses'])}")
    if iocs.get("domains"):
        print(f"│  Domains:  {', '.join(iocs['domains'])}")
    if iocs.get("urls"):
        for u in iocs["urls"]:
            print(f"│  URL:      {u}")
    if iocs.get("file_hashes"):
        for h in iocs["file_hashes"]:
            print(f"│  Hash:     {h}")
    if iocs.get("email_addresses"):
        print(f"│  Emails:   {', '.join(iocs['email_addresses'])}")
    if iocs.get("malicious_packages"):
        print(f"│  Packages: {', '.join(iocs['malicious_packages'])}")
    if iocs.get("mining_wallet"):
        print(f"│  Wallet:   {iocs['mining_wallet'][:40]}...")
    print("└────────────────────────────────────────────────────────────────┘")

    print("\n[ LLM ANALYSIS ]")
    for line in report["llm_analysis"].split("\n"):
        print(f"│  {line}")
    print("└────────────────────────────────────────────────────────────────┘")

    print("\n[ NETWORK ACTIVITY ]")
    for line in report["network_activity_summary"].split("\n"):
        print(f"│  {line[:75]}")
    print("└────────────────────────────────────────────────────────────────┘")

    print()


def _wrap(text: str, width: int) -> str:
    """Wrap text for display inside report boxes."""
    lines = textwrap.wrap(text, width=width)
    if len(lines) <= 1:
        return text
    padding = "\n│" + " " * 20
    return padding.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="IoC Knowledge Generation Engine — PoC Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          python main.py --scenario all    Analyze all attack scenarios
          python main.py --scenario 1      Analyze Emotet phishing campaign
          python main.py --scenario 2      Analyze LockBit ransomware
          python main.py --list            Show available scenarios
        """),
    )
    parser.add_argument(
        "--scenario", "-s",
        type=str,
        default=None,
        help="Scenario number (1-5) or 'all' to analyze all scenarios",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available attack scenarios",
    )
    parser.add_argument(
        "--model", "-m",
        type=str,
        default="google/flan-t5-base",
        help="HuggingFace model to use (default: google/flan-t5-base)",
    )
    parser.add_argument(
        "--top-k", "-k",
        type=int,
        default=5,
        help="Number of MITRE techniques to retrieve per scenario (default: 5)",
    )
    parser.add_argument(
        "--save-json",
        type=str,
        default=None,
        help="Save reports to a JSON file",
    )

    args = parser.parse_args()

    if args.list:
        print_scenario_menu()
        sys.exit(0)

    if args.scenario is None:
        parser.print_help()
        print("\nError: Please specify --scenario or --list")
        sys.exit(1)

    engine = KnowledgeGenerationEngine(model_name=args.model)

    reports = []

    if args.scenario.lower() == "all":
        print("\n[*] Analyzing all scenarios...\n")
        reports = engine.analyze_all_scenarios(retrieval_k=args.top_k)
    else:
        try:
            scenario_num = int(args.scenario)
            scenario_id = f"SC-{scenario_num:03d}"
        except ValueError:
            scenario_id = args.scenario

        available = get_scenario_ids()
        if scenario_id not in available:
            print(f"[!] Scenario '{scenario_id}' not found.")
            print(f"    Available: {', '.join(available)}")
            sys.exit(1)

        report = engine.analyze_scenario(scenario_id, retrieval_k=args.top_k)
        if report:
            reports.append(report)

    for report in reports:
        print_report(report)

    if args.save_json and reports:
        with open(args.save_json, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        print(f"\n[*] Reports saved to {args.save_json}")

    print(f"\n{'=' * 70}")
    print(f"  Analysis complete. {len(reports)} scenario(s) processed.")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
