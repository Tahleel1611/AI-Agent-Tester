import asyncio

from main import DOMPayload
import agents.graph as graph_module
from agents.nodes import security_agent_node
from agents.graph import run_swarm


def payload_with_all_specialist_signals() -> DOMPayload:
    return DOMPayload.model_validate({
        "url": "https://example.com/checkout",
        "title": "Checkout",
        "text": "select * from users",
        "dom_structure": [{"tag": "img", "text": ""}],
        "forms": [{"action": "", "inputs": [{"name": "email", "has_validation": False}]}],
        "buttons": [{"text": "", "aria_label": None}],
    })


def test_swarm_returns_deterministic_aggregated_findings() -> None:
    first = asyncio.run(run_swarm(payload_with_all_specialist_signals(), "scan-1"))
    second = asyncio.run(run_swarm(payload_with_all_specialist_signals(), "scan-1"))

    assert first.model_dump() == second.model_dump()
    assert first.summary == {"total": 5, "security": 2, "ui_ux": 2, "logic": 1}
    assert all(finding.remediation_prompt for finding in first.bugs)


def test_specialist_failure_isolated_to_node(monkeypatch) -> None:
    async def failing_security_node(state):
        return {"findings": [], "errors": {"security": "provider unavailable"}}

    monkeypatch.setattr(graph_module, "security_agent_node", failing_security_node)
    response = asyncio.run(run_swarm(payload_with_all_specialist_signals(), "scan-2"))

    assert response.summary["security"] == 0
    assert response.summary["ui_ux"] == 2
    assert response.summary["logic"] == 1