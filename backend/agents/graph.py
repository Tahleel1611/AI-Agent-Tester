from __future__ import annotations

import asyncio
from typing import Any

from langgraph.graph import END, START, StateGraph

from main import DOMPayload, Finding, ScanResponse, generate_remediation_prompt
from middleware import scan_id_context
from .nodes import (
    aggregator_node,
    logic_agent_node,
    normalizer_node,
    security_agent_node,
    ui_ux_agent_node,
)
from .state import AgentState


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("normalizer", normalizer_node)
    graph.add_node("specialists", specialist_fan_out_node)
    graph.add_node("aggregator", aggregator_node)
    graph.add_edge(START, "normalizer")
    graph.add_edge("normalizer", "specialists")
    graph.add_edge("specialists", "aggregator")
    graph.add_edge("aggregator", END)
    return graph.compile()


async def specialist_fan_out_node(state: AgentState) -> dict[str, Any]:
    """Run all specialists concurrently and merge their isolated results once."""
    results = await asyncio.gather(
        security_agent_node(state), ui_ux_agent_node(state), logic_agent_node(state)
    )
    findings = [finding for result in results for finding in result.get("findings", [])]
    errors = {
        name: message
        for result in results
        for name, message in result.get("errors", {}).items()
    }
    return {"findings": findings, "errors": errors}


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
    for finding in result.get("aggregated_findings", []):
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
