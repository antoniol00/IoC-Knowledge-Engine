"""
Knowledge Generation Engine module.

Central engine that combines the Telemetry Processor and MITRE ATT&CK
Knowledge Base with a HuggingFace LLM to generate contextualized threat
intelligence reports.
"""

import textwrap
from datetime import datetime, timezone

from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

from .knowledge_base import MitreKnowledgeBase
from .telemetry_processor import TelemetryProcessor, ProcessedScenario

ANALYSIS_PROMPT_TEMPLATE = textwrap.dedent("""\
You are a cybersecurity threat intelligence analyst. Analyze the following
telemetry data and provide a structured threat assessment.

TELEMETRY DATA:
{telemetry_summary}

RELEVANT MITRE ATT&CK TECHNIQUES (retrieved from knowledge base):
{mitre_context}

Based on the telemetry and MITRE ATT&CK context, provide:
1. Attack classification and adversary profile
2. Mapped TTPs (Tactics, Techniques, and Procedures)
3. Risk assessment (Critical/High/Medium/Low)
4. Recommended defensive actions

Analysis:""")


class KnowledgeGenerationEngine:
    """
    Central engine for IoC-driven knowledge generation.

    Combines:
    - TelemetryProcessor: ingests and summarizes raw telemetry
    - MitreKnowledgeBase: retrieves relevant ATT&CK techniques via RAG
    - HuggingFace LLM: generates contextualized threat analysis

    The engine processes each attack scenario through a RAG pipeline:
    telemetry → semantic search over ATT&CK → LLM analysis → knowledge report.
    """

    def __init__(
        self,
        model_name: str = "google/flan-t5-base",
        telemetry_path: str = None,
        knowledge_path: str = None,
        max_new_tokens: int = 512,
    ):
        """
        Initialize the Knowledge Generation Engine.

        Args:
            model_name: HuggingFace model ID for text generation.
            telemetry_path: Path to simulated_telemetry.json.
            knowledge_path: Path to mitre_attck_knowledge.json.
            max_new_tokens: Maximum number of tokens the LLM can generate.
        """
        print("=" * 70)
        print("  IoC Knowledge Generation Engine — Initializing")
        print("=" * 70)

        # Initialize sub-components
        self.knowledge_base = MitreKnowledgeBase(knowledge_path)
        self.telemetry_processor = TelemetryProcessor(telemetry_path)

        # Initialize HuggingFace LLM (direct model + tokenizer for compatibility)
        print(f"[*] Loading LLM: {model_name} ...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
        self.max_new_tokens = max_new_tokens
        self.model_name = model_name
        print(f"    LLM loaded successfully ({model_name}).")
        print("=" * 70)

    def analyze_scenario(
        self, scenario_id: str, retrieval_k: int = 5
    ) -> dict | None:
        """
        Analyze a single telemetry scenario.

        Args:
            scenario_id: Scenario identifier (e.g., 'SC-001').
            retrieval_k: Number of MITRE techniques to retrieve.

        Returns:
            Knowledge report dictionary, or None if scenario not found.
        """
        processed = self.telemetry_processor.process_scenario_by_id(scenario_id)
        if processed is None:
            print(f"[!] Scenario '{scenario_id}' not found.")
            return None

        return self._generate_knowledge(processed, retrieval_k)

    def analyze_all_scenarios(self, retrieval_k: int = 5) -> list[dict]:
        """
        Analyze all telemetry scenarios.

        Args:
            retrieval_k: Number of MITRE techniques to retrieve per scenario.

        Returns:
            List of knowledge report dictionaries.
        """
        all_processed = self.telemetry_processor.process_all_scenarios()
        reports = []
        for processed in all_processed:
            report = self._generate_knowledge(processed, retrieval_k)
            reports.append(report)
        return reports

    def _generate_knowledge(
        self, processed: ProcessedScenario, retrieval_k: int
    ) -> dict:
        print(f"\n{'─' * 70}")
        print(f"  Analyzing: {processed.name} ({processed.scenario_id})")
        print(f"  Severity: {processed.severity}")
        print("-" * 50)

        print("[*] Querying knowledge base...")
        retrieved_techniques = self.knowledge_base.retrieve_relevant_techniques(
            processed.natural_language_summary, k=retrieval_k
        )

        mitre_context = "\n\n".join(
            f"--- Technique {i+1} ---\n{doc.page_content}"
            for i, doc in enumerate(retrieved_techniques)
        )

        mapped_ttps = []
        for doc in retrieved_techniques:
            mapped_ttps.append({
                "technique_id": doc.metadata["technique_id"],
                "technique_name": doc.metadata["name"],
                "tactic": doc.metadata["tactic"],
            })

        print(f"    Retrieved {len(retrieved_techniques)} relevant techniques:")
        for ttp in mapped_ttps:
            print(
                f"      - {ttp['technique_id']}: {ttp['technique_name']} "
                f"({ttp['tactic']})"
            )

        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            telemetry_summary=processed.natural_language_summary,
            mitre_context=mitre_context,
        )

        print("[*] Generating knowledge via LLM...")

        # Tokenize with truncation to fit model's input limit
        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            max_length=512,
            truncation=True,
        )
        outputs = self.model.generate(
            **inputs,
            max_new_tokens=self.max_new_tokens,
            do_sample=False,
        )
        llm_response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"    LLM analysis complete ({len(llm_response)} chars).")

        report = self._build_report(processed, mapped_ttps, llm_response)
        return report

    def _build_report(
        self,
        processed: ProcessedScenario,
        mapped_ttps: list[dict],
        llm_analysis: str,
    ) -> dict:
        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "model_used": self.model_name,
                "scenario_id": processed.scenario_id,
                "scenario_name": processed.name,
            },
            "threat_assessment": {
                "severity": processed.severity,
                "description": processed.description,
                "malware_family": processed.malware_info.get("family", "Unknown"),
                "malware_type": processed.malware_info.get("type", "Unknown"),
            },
            "mitre_attck_mapping": {
                "mapped_ttps": mapped_ttps,
                "tactic_coverage": list(set(t["tactic"] for t in mapped_ttps)),
            },
            "indicators_of_compromise": processed.iocs,
            "llm_analysis": llm_analysis,
            "network_activity_summary": processed.network_summary,
            "honeypot_activity_summary": processed.honeypot_summary,
        }
