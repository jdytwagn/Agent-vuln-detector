from __future__ import annotations

import os
from pathlib import Path

from fastapi import Header, HTTPException

from core.env import get_env


def resolve_api_path(path: str, *, must_exist: bool = False, workspace_root: Path | None = None) -> Path:
    """Resolve an API-supplied path and keep it inside the configured workspace."""
    resolved = Path(path).expanduser().resolve()
    if must_exist and not resolved.exists():
        raise ValueError(f"Path does not exist: {path}")
    if os.environ.get("AGENT_DETECTOR_ALLOW_ANY_PATH", "").lower() in {"1", "true", "yes"}:
        return resolved
    root = (workspace_root or Path.cwd()).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            "API file access is restricted to the project workspace. "
            "Set AGENT_DETECTOR_ALLOW_ANY_PATH=true only in a trusted local environment."
        ) from exc
    return resolved


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
