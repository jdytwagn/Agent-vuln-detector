from __future__ import annotations

from fastapi import Header, HTTPException

from core.env import get_env


def require_api_key(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    expected = get_env("AGENT_DETECTOR_API_KEY")
    if not expected:
        return
    bearer = ""
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization[7:].strip()
    provided = x_api_key or bearer
    if provided != expected:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
