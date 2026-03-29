"""
MITRE ATT&CK Knowledge Base module.

Loads the curated MITRE ATT&CK technique database, creates embeddings,
and builds a FAISS vector store for semantic retrieval (RAG).
"""

import json
import os

from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS


# Path to the MITRE ATT&CK knowledge JSON
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
MITRE_KNOWLEDGE_PATH = os.path.join(DATA_DIR, "mitre_attck_knowledge.json")

# Embedding model (small, fast, runs on CPU)
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class MitreKnowledgeBase:
    """
    Manages the MITRE ATT&CK knowledge base with semantic search capabilities.

    Loads technique descriptions from a JSON file, converts them into
    LangChain Documents, and indexes them in a FAISS vector store for
    efficient similarity-based retrieval.
    """

    def __init__(self, knowledge_path: str = None):
        """
        Initialize the knowledge base.

        Args:
            knowledge_path: Path to mitre_attck_knowledge.json. Defaults to
                            the bundled data file.
        """
        self.knowledge_path = knowledge_path or MITRE_KNOWLEDGE_PATH
        self.documents = []
        self.vector_store = None
        self.embeddings = None

        self._load_knowledge()
        self._build_vector_store()

    def _load_knowledge(self):
        """Load MITRE ATT&CK techniques and convert to LangChain Documents."""
        print("[*] Loading MITRE ATT&CK knowledge base...")

        with open(self.knowledge_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for technique in data["techniques"]:
            # Build a rich text representation for embedding
            sub_techniques = technique.get("sub_techniques", [])
            sub_tech_text = (
                f"Sub-techniques: {', '.join(sub_techniques)}"
                if sub_techniques
                else ""
            )

            content = (
                f"MITRE ATT&CK Technique {technique['technique_id']}: "
                f"{technique['name']}\n"
                f"Tactic: {technique['tactic']}\n"
                f"Description: {technique['description']}\n"
                f"{sub_tech_text}\n"
                f"Detection: {technique['detection']}\n"
                f"Platforms: {', '.join(technique.get('platforms', []))}"
            )

            doc = Document(
                page_content=content,
                metadata={
                    "technique_id": technique["technique_id"],
                    "name": technique["name"],
                    "tactic": technique["tactic"],
                    "platforms": technique.get("platforms", []),
                    "sub_techniques": sub_techniques,
                },
            )
            self.documents.append(doc)

        print(f"    Loaded {len(self.documents)} MITRE ATT&CK techniques.")

    def _build_vector_store(self):
        """Build FAISS vector store from technique documents."""
        print("[*] Building FAISS vector store with embeddings...")
        self.embeddings = HuggingFaceEmbeddings(
            model_name=EMBEDDING_MODEL,
            model_kwargs={"device": "cpu"},
            encode_kwargs={"normalize_embeddings": True},
        )
        self.vector_store = FAISS.from_documents(self.documents, self.embeddings)
        print("    FAISS index built successfully.")

    def retrieve_relevant_techniques(self, query: str, k: int = 5) -> list[Document]:
        """
        Retrieve the top-k most relevant MITRE ATT&CK techniques for a query.

        Args:
            query: Natural-language description of observed behavior.
            k: Number of techniques to retrieve.

        Returns:
            List of LangChain Documents with technique details.
        """
        results = self.vector_store.similarity_search(query, k=k)
        return results

    def get_technique_summary(self, technique_id: str) -> str | None:
        """
        Get the full text summary for a specific technique ID.

        Args:
            technique_id: MITRE ATT&CK ID (e.g., 'T1566').

        Returns:
            Technique summary string, or None if not found.
        """
        for doc in self.documents:
            if doc.metadata["technique_id"] == technique_id:
                return doc.page_content
        return None
