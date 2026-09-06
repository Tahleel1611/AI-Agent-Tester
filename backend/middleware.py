import asyncio
import contextvars
from collections.abc import Awaitable, Callable
from uuid import UUID, uuid4

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp


scan_id_context: contextvars.ContextVar[str] = contextvars.ContextVar(
    "scan_id", default=""
)


def _validated_scan_id(value: str | None) -> str:
    """Accept UUID correlation IDs while replacing malformed or oversized values."""
    if value:
        try:
            return str(UUID(value))
        except ValueError:
            pass
    return str(uuid4())


async def correlation_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    scan_id = _validated_scan_id(request.headers.get("X-Scan-ID"))
    token = scan_id_context.set(scan_id)
    try:
        response = await call_next(request)
        response.headers["X-Scan-ID"] = scan_id
        return response
    finally:
        scan_id_context.reset(token)


class RequestTimeoutMiddleware:
    """Terminate requests that exceed the configured orchestration budget."""

    def __init__(self, app: ASGIApp, timeout_seconds: float) -> None:
        self.app = app
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_with_state(message: dict) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await asyncio.wait_for(
                self.app(scope, receive, send_with_state), self.timeout_seconds
            )
        except (asyncio.TimeoutError, TimeoutError):
            if response_started:
                return
            timeout_response = JSONResponse(
                status_code=504,
                content={
                    "error": "request_timeout",
                    "message": "The scan exceeded the configured processing timeout.",
                    "scan_id": scan_id_context.get(),
                },
            )
            await timeout_response(scope, receive, send)
