"""FastAPI orchestration layer for the AI Web Tester Phase 2 prototype.

The agent and RAG functions in this module are deliberately local mocks.  Replace
their bodies with calls to LangChain/AutoGen and a vector store without changing
the API contract exposed by ``POST /scan``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field

from config import get_settings
from middleware import RequestTimeoutMiddleware, correlation_middleware, scan_id_context


class DOMElement(BaseModel):
    """A compact representation of an element extracted by the extension."""

    model_config = ConfigDict(extra="allow")

    tag: str = Field(min_length=1, max_length=100)
    id: str | None = Field(default=None, max_length=500)
    classes: list[str] = Field(default_factory=list)
    text: str = Field(default="", max_length=2_000)
    has_inline_handler: bool = Field(default=False, alias="hasInlineHandler")


class Link(BaseModel):
    text: str = ""
    href: str | None = None
    aria_label: str | None = None


class Button(BaseModel):
    text: str = ""
    button_type: str | None = None
    aria_label: str | None = None
    disabled: bool = False
    visible: bool | None = None


class FormField(BaseModel):
    name: str | None = None
    field_type: str | None = None
    value: str | None = None
    required: bool = False
    placeholder: str | None = None
    aria_label: str | None = None
    has_validation: bool | None = None


class Form(BaseModel):
    action: str | None = None
    method: str | None = None
    id: str | None = None
    inputs: list[FormField] = Field(default_factory=list)


class Image(BaseModel):
    src: str | None = None
    alt: str | None = None
    aria_label: str | None = None


class DOMPayload(BaseModel):
    """Validated page context accepted from Phase 1 and richer future clients."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    url: AnyHttpUrl
    title: str = Field(default="", max_length=1_000)
    text: str = Field(default="", max_length=50_000)
    headings: list[str] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    buttons: list[Button] = Field(default_factory=list)
    forms: list[Form] = Field(default_factory=list)
    inputs: list[FormField] = Field(default_factory=list)
    textareas: list[FormField] = Field(default_factory=list)
    images: list[Image] = Field(default_factory=list)

    # Backwards-compatible fields emitted by the current Phase 1 extension.
    text_content: str = Field(default="", max_length=50_000)
    dom_structure: list[DOMElement] = Field(default_factory=list)
    captured_at: datetime | None = None

    @property
    def page_text(self) -> str:
        return self.text or self.text_content

    @property
    def all_inputs(self) -> list[FormField]:
        return [*self.inputs, *self.textareas, *(field for form in self.forms for field in form.inputs)]


Severity = Literal["low", "medium", "high", "critical"]


class Finding(BaseModel):
    id: str
    category: Literal["Security", "UI/UX", "Logic"]
    severity: Severity
    title: str
    description: str
    signature: str
    dom_snippet: str
    recurring_issue: bool = False
    historical_context: str | None = None
    remediation_prompt: str = ""


class ScanResponse(BaseModel):
    scan_id: str
    url: AnyHttpUrl
    title: str
    bugs: list[Finding]
    summary: dict[str, int]


settings = get_settings()
app = FastAPI(title="AI Web Tester API", version="0.2.0")

app.add_middleware(RequestTimeoutMiddleware, timeout_seconds=settings.api_timeout_seconds)
app.middleware("http")(correlation_middleware)

# Chrome extensions use a chrome-extension:// origin.  Regex permits any locally
# loaded extension ID while explicit localhost origins help browser-based clients.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_cors_origins,
    allow_origin_regex=settings.allowed_cors_origin_regex,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def generate_remediation_prompt(bug_data: Finding, dom_snippet: str, is_recurring: bool) -> str:
    """Build a copy-paste-ready implementation request for a developer or coding AI."""
    recurring_note = (
        "WARNING: This is a recurring regression. Include a regression test that prevents it from returning."
        if is_recurring else "No matching historical issue was found."
    )
    return f"""{recurring_note}\n\nRole: Senior Web Developer\n\nTask: Resolve the {bug_data.severity}-severity {bug_data.category} issue: {bug_data.title}.\n\nContext: {bug_data.description}\n\nFailing Code Snippet:\n{dom_snippet or '(No relevant DOM text was captured.)'}\n\nRequirements:\n- Preserve the existing user flow and public API behavior.\n- Implement the fix on both client and server where validation or security is involved.\n- Add an automated regression test covering the failing case.\n- Follow WCAG-accessible semantics for UI changes.\n- Explain the root cause and the verification performed in the pull request."""


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(payload: DOMPayload) -> ScanResponse:
    """Run the Phase 3 specialist graph and preserve the public scan contract."""
    from agents.graph import run_swarm
    from agents.nodes import bug_memory

    response = await run_swarm(payload, scan_id_context.get())
    for finding in response.bugs:
        bug_memory.store_bug(finding)
    return response
