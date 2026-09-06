import asyncio

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from main import DOMPayload, app
from config import Settings
from middleware import RequestTimeoutMiddleware, scan_id_context


client = TestClient(app)


def test_health_check() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Scan-ID"]


def test_mock_llm_provider_is_the_safe_default() -> None:
    assert Settings().llm_provider == "mock"


def test_scan_preserves_valid_correlation_id() -> None:
    payload = {"url": "https://example.com", "title": "Example"}
    scan_id = "12345678-1234-5678-1234-567812345678"

    response = client.post("/scan", json=payload, headers={"X-Scan-ID": scan_id})

    assert response.status_code == 200
    assert response.headers["X-Scan-ID"] == scan_id
    assert response.json()["scan_id"] == scan_id


def test_invalid_correlation_id_is_replaced() -> None:
    response = client.get("/health", headers={"X-Scan-ID": "not-a-uuid"})

    assert response.status_code == 200
    assert response.headers["X-Scan-ID"] != "not-a-uuid"
    assert scan_id_context.get() == ""


def test_scan_accepts_current_extension_payload() -> None:
    payload = {
        "url": "https://example.com/checkout",
        "title": "Checkout",
        "text_content": "Checkout form",
        "dom_structure": [
            {"tag": "img", "text": "", "classes": [], "hasInlineHandler": False}
        ],
        "captured_at": "2026-09-05T12:00:00Z",
    }

    response = client.post("/scan", json=payload)

    assert response.status_code == 200
    validated_payload = DOMPayload.model_validate(payload)
    assert validated_payload.dom_structure[0].has_inline_handler is False
    body = response.json()
    assert body["url"] == payload["url"]
    assert body["title"] == payload["title"]
    assert body["summary"]["total"] == len(body["bugs"])
    assert body["bugs"][0]["signature"] == "uiux:image-missing-accessible-name"


def test_scan_accepts_richer_payload_and_returns_all_agent_categories() -> None:
    payload = {
        "url": "https://example.com/account",
        "title": "Account",
        "text": "select * from users",
        "forms": [{"action": "", "inputs": [{"name": "email", "has_validation": False}]}],
        "images": [{"src": "/logo.svg", "alt": "Logo"}],
        "buttons": [{"text": "", "aria_label": None}],
    }

    response = client.post("/scan", json=payload)

    assert response.status_code == 200
    categories = {finding["category"] for finding in response.json()["bugs"]}
    assert categories == {"Security", "UI/UX", "Logic"}


def test_scan_rejects_invalid_url() -> None:
    response = client.post("/scan", json={"url": "not-a-url"})

    assert response.status_code == 422


def test_scan_results_are_deterministic() -> None:
    payload = {
        "url": "https://example.com/form",
        "title": "Form",
        "forms": [{"action": "", "inputs": [{"name": "email"}]}],
    }

    first = client.post("/scan", json=payload).json()
    second = client.post("/scan", json=payload).json()

    assert first["bugs"] == second["bugs"]
    assert first["summary"] == second["summary"]


def test_timeout_middleware_returns_structured_504() -> None:
    timeout_app = FastAPI()

    @timeout_app.get("/slow")
    async def slow_endpoint() -> dict[str, bool]:
        await asyncio.sleep(0.05)
        return {"ok": True}

    timeout_app.add_middleware(RequestTimeoutMiddleware, timeout_seconds=0.001)

    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=timeout_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/slow")

    response = asyncio.run(request())

    assert response.status_code == 504
    assert response.json()["error"] == "request_timeout"
