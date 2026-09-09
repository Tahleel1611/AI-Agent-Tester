"""Local Qdrant-backed semantic memory for previously discovered bugs."""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import uuid4

from fastembed import TextEmbedding
from qdrant_client import QdrantClient, models

from main import Finding

logger = logging.getLogger(__name__)


class BugMemory:
    """A best-effort, persistent semantic memory for finalized findings."""

    collection_name = "historical_bugs"
    embedding_model = "BAAI/bge-small-en-v1.5"

    def __init__(self, path: str | Path = "local_qdrant") -> None:
        self._client: QdrantClient | None = None
        self._embedder: TextEmbedding | None = None
        self._available = False
        try:
            self._client = QdrantClient(path=str(path))
            self._embedder = TextEmbedding(model_name=self.embedding_model)
            self.initialize()
            self._available = True
        except Exception as error:
            logger.warning("Historical bug memory is unavailable: %s", error)
            self._client = None
            self._embedder = None

    def initialize(self) -> None:
        """Create the collection once, with a vector size from the embedder."""
        if self._client is None or self._embedder is None:
            raise RuntimeError("BugMemory has not been initialized")
        if not self._client.collection_exists(self.collection_name):
            vector_size = len(self._embed(self.embedding_model))
            self._client.create_collection(
                collection_name=self.collection_name,
                vectors_config=models.VectorParams(
                    size=vector_size, distance=models.Distance.COSINE
                ),
            )

    def _embed(self, text: str) -> list[float]:
        if self._embedder is None:
            raise RuntimeError("Embedding model is unavailable")
        return list(next(iter(self._embedder.embed([text]))))

    @staticmethod
    def _document(description: str, dom_snippet: str) -> str:
        return f"Bug description:\n{description}\n\nRelevant DOM:\n{dom_snippet}".strip()

    def store_bug(self, finding: Finding) -> None:
        """Persist a finalized finding; memory errors never fail a scan."""
        if not self._available or self._client is None:
            return
        try:
            self._client.upsert(
                collection_name=self.collection_name,
                points=[models.PointStruct(
                    id=str(uuid4()),
                    vector=self._embed(self._document(finding.description, finding.dom_snippet)),
                    payload={
                        "category": finding.category,
                        "severity": finding.severity,
                        "signature": finding.signature,
                        "description": finding.description,
                    },
                )],
            )
        except Exception as error:
            logger.warning("Could not store historical bug: %s", error)

    def check_recurrence(
        self, description: str, dom_snippet: str, similarity_threshold: float = 0.85
    ) -> bool:
        """Return True when a historical bug exceeds the cosine threshold."""
        if not self._available or self._client is None:
            return False
        try:
            result = self._client.query_points(
                collection_name=self.collection_name,
                query=self._embed(self._document(description, dom_snippet)),
                limit=1,
                with_payload=False,
            )
            return bool(result.points and result.points[0].score >= similarity_threshold)
        except Exception as error:
            logger.warning("Could not query historical bugs: %s", error)
            return False
