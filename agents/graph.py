from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from main import DOMPayload, Finding, ScanResponse, generate_remediation_prompt
from middleware import scan_id_context
from .nodes import aggregator_node, logic_agent_node, normalizer_node, security_agent_node, ui_ux_agent_node
from .state import AgentState


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("normalizer", normalizer_node)
    graph.add_node("security", security_agent_node)
    graph.add_node("ui_ux", ui_ux_agent_node)
    graph.add_node("logic", logic_agent_node)
    graph.add_node("aggregator", aggregator_node)
    graph.add_edge(START, "normalizer")
    graph.add_edge("normalizer", "security")
    graph.add_edge("normalizer", "ui_ux")
    graph.add_edge("normalizer", "logic")
    graph.add_edge("security", "aggregator")
    graph.add_edge("ui_ux", "aggregator")
    graph.add_edge("logic", "aggregator")
    graph.add_edge("aggregator", END)
    return graph.compile()


swarm_graph = build_graph()


async def run_swarm(payload: DOMPayload, scan_id: str) -> ScanResponse:
    """Execute the specialist graph and adapt its state to the existing API contract."""
    result: AgentState = await swarm_graph.ainvoke({
        "payload": payload,
        "scan_id": scan_id,
        "findings": [],
        "errors": {},
    })
    bugs: list[Finding] = []
    for finding in result.get("findings", []):
        historical = {"message": "Mock RAG match: a similar issue was reported in a prior scan."}
        finding.recurring_issue = True
        finding.historical_context = historical["message"]
        finding.remediation_prompt = generate_remediation_prompt(
            finding, finding.dom_snippet, finding.recurring_issue
        )
        bugs.append(finding)
    return ScanResponse(
        scan_id=scan_id or scan_id_context.get(),
        url=payload.url,
        title=payload.title,
        bugs=bugs,
        summary={
            "total": len(bugs),
            "security": sum(finding.category == "Security" for finding in bugs),
            "ui_ux": sum(finding.category == "UI/UX" for finding in bugs),
            "logic": sum(finding.category == "Logic" for finding in bugs),
        },
    )
