from __future__ import annotations

from typing import Any

from config import get_settings


def get_llm() -> Any | None:
    """Create the configured LangChain chat model, or None for deterministic mock mode."""
    settings = get_settings()
    if settings.llm_provider == "mock":
        return None

    if settings.llm_provider == "openai":
        from langchain_openai import ChatOpenAI

        if not settings.llm_api_key:
            raise RuntimeError("LLM_API_KEY is required when LLM_PROVIDER=openai")
        return ChatOpenAI(
            model=settings.llm_model,
            api_key=settings.llm_api_key,
            temperature=0,
        )

    if settings.llm_provider == "oci":
        from langchain_community.chat_models import ChatOCIGenAI

        auth_type = settings.oci_auth_type
        if not settings.oci_compartment_id or not settings.oci_service_endpoint:
            raise RuntimeError(
                "OCI_COMPARTMENT_ID and OCI_SERVICE_ENDPOINT are required when "
                "LLM_PROVIDER=oci"
            )
        kwargs: dict[str, Any] = {
            "model_id": settings.llm_model,
            "service_endpoint": settings.oci_service_endpoint,
            "compartment_id": settings.oci_compartment_id,
            "auth_type": auth_type,
            "model_kwargs": {"temperature": 0},
        }
        if settings.oci_profile:
            # ChatOCIGenAI reads named profiles from ~/.oci/config.
            kwargs["auth_profile"] = settings.oci_profile
        return ChatOCIGenAI(**kwargs)

    raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")
