from __future__ import annotations

import asyncio
from typing import Any

from main import DOMPayload, Finding


def _snippet(payload: DOMPayload, fallback: str) -> str:
    return (payload.page_text or fallback).strip()[:500]


def _finding(
    *,
    payload: DOMPayload,
    category: str,
    severity: str,
    title: str,
    description: str,
    signature: str,
    scan_id: str,
) -> Finding:
    """Create a schema-valid finding; live providers can replace this adapter later."""
    return Finding(
        id=f"{scan_id}:{signature}",
        category=category,
        severity=severity,
        title=title,
        description=description,
        signature=signature,
        dom_snippet=_snippet(payload, title),
    )


def normalizer_node(state: dict[str, Any]) -> dict[str, Any]:
    payload: DOMPayload = state["payload"]
    return {
        "normalized_evidence": {
            "page_text": payload.page_text[:10_000],
            "dom_elements": [element.model_dump() for element in payload.dom_structure[:150]],
            "forms": [form.model_dump() for form in payload.forms[:50]],
            "inputs": [field.model_dump() for field in payload.all_inputs[:100]],
            "images": [image.model_dump() for image in payload.images[:100]],
            "buttons": [button.model_dump() for button in payload.buttons[:100]],
        }
    }


async def security_agent_node(state: dict[str, Any]) -> dict[str, Any]:
    try:
        payload: DOMPayload = state["payload"]
        evidence = state["normalized_evidence"]
        page_text = evidence["page_text"].lower()
        findings: list[Finding] = []
        if any(term in page_text for term in ("sql", "select ", "<script", "javascript:", "drop table")):
            findings.append(_finding(
                payload=payload, category="Security", severity="high",
                title="Potential injection exposure",
                description="Page content contains injection-like input patterns that need server-side handling.",
                signature="security:potential-injection", scan_id=state["scan_id"],
            ))
        inputs = evidence["inputs"]
        if inputs and (any(field.get("has_validation") is False for field in inputs) or not evidence["forms"]):
            findings.append(_finding(
                payload=payload, category="Security", severity="medium",
                title="Form validation requires review",
                description="Inputs were found without evidence of complete validation. Enforce validation on the server.",
                signature="security:missing-server-validation", scan_id=state["scan_id"],
            ))
        await asyncio.sleep(0)
        return {"findings": findings}
    except Exception as error:
        return {"findings": [], "errors": {"security": str(error)}}


async def ui_ux_agent_node(state: dict[str, Any]) -> dict[str, Any]:
    try:
        payload: DOMPayload = state["payload"]
        evidence = state["normalized_evidence"]
        findings: list[Finding] = []
        if any(not (image.get("alt") or image.get("aria_label")) for image in evidence["images"]) or any(
            element.get("tag") == "img" and not element.get("text") for element in evidence["dom_elements"]
        ):
            findings.append(_finding(
                payload=payload, category="UI/UX", severity="medium",
                title="Image accessibility gap",
                description="One or more images lack descriptive alternative text or an accessible label.",
                signature="uiux:image-missing-accessible-name", scan_id=state["scan_id"],
            ))
        if any(button.get("visible") is False or not (button.get("text") or button.get("aria_label")) for button in evidence["buttons"]):
            findings.append(_finding(
                payload=payload, category="UI/UX", severity="medium",
                title="Button visibility or accessible-name issue",
                description="A button is hidden or has no readable label, which can block keyboard and screen-reader users.",
                signature="uiux:button-accessibility", scan_id=state["scan_id"],
            ))
        await asyncio.sleep(0)
        return {"findings": findings}
    except Exception as error:
        return {"findings": [], "errors": {"ui_ux": str(error)}}


async def logic_agent_node(state: dict[str, Any]) -> dict[str, Any]:
    try:
        payload: DOMPayload = state["payload"]
        evidence = state["normalized_evidence"]
        findings: list[Finding] = []
        forms = evidence["forms"]
        if any(not form.get("action") for form in forms):
            findings.append(_finding(
                payload=payload, category="Logic", severity="low",
                title="Form submission route is unclear",
                description="A form has no declared action. Confirm its JavaScript submission path and failure handling.",
                signature="logic:form-submission-route", scan_id=state["scan_id"],
            ))
        elif forms or evidence["inputs"]:
            findings.append(_finding(
                payload=payload, category="Logic", severity="low",
                title="Form submission flow should be verified",
                description="A form or input was detected. Test valid, invalid, duplicate, and network-failure submission paths.",
                signature="logic:form-submission-review", scan_id=state["scan_id"],
            ))
        await asyncio.sleep(0)
        return {"findings": findings}
    except Exception as error:
        return {"findings": [], "errors": {"logic": str(error)}}


def aggregator_node(state: dict[str, Any]) -> dict[str, Any]:
    unique: dict[str, Finding] = {}
    for finding in state.get("findings", []):
        unique.setdefault(finding.signature, finding)
    return {"findings": sorted(unique.values(), key=lambda finding: finding.signature)}
