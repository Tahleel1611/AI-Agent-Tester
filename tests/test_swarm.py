import asyncio

from main import DOMPayload
from agents.graph import run_swarm
from agents.nodes import security_agent_node


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


def test_specialist_failure_isolated_to_node() -> None:
    original = security_agent_node.__globals__["_finding"]

    def failing_finding(**kwargs):
        raise RuntimeError("provider unavailable")

    security_agent_node.__globals__["_finding"] = failing_finding
    try:
        response = asyncio.run(run_swarm(payload_with_all_specialist_signals(), "scan-2"))
    finally:
        security_agent_node.__globals__["_finding"] = original

    assert response.summary["security"] == 0
    assert response.summary["ui_ux"] == 2
    assert response.summary["logic"] == 1