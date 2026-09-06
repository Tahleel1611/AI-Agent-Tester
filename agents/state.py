from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from main import Finding


class AgentState(TypedDict, total=False):
    """Shared state passed through the Phase 3 specialist graph."""

    payload: Any
    scan_id: str
    normalized_evidence: dict[str, Any]
    findings: Annotated[list[Finding], operator.add]
    errors: dict[str, str]
