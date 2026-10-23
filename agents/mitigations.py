from __future__ import annotations

import re


OBSERVATION_ONLY_FILTERS = {
    "strlen",
    "sizeof",
    "null check",
    "error handling",
    "set null",
    "ownership transfer",
    "constant format string",
    "allowlist",
    "base directory check",
    "fgets",
}

MITIGATION_CALLS = {"validate", "sanitize", "escape", "is_allowed", "whitelist_check", "canonicalize_path"}
INPUT_CALLS = {"fgets", "gets", "fread", "read", "getline", "scanf", "fscanf", "recv", "recvfrom"}


def is_string_literal(value: str) -> bool:
    return bool(re.match(r"""^(?:u8|u|U|L)?["']""", value.strip()))


def has_unbounded_string_conversion(fmt: str) -> bool:
    """True when a scanf-style format can write an unbounded string."""
    text = fmt.strip()
    if not is_string_literal(text):
        return True
    body = text
    bounded = re.sub(r"%[-+ #0]*(?:\d+\$)?\d+[s\[]", "", body)
    return bool(re.search(r"%[-+ #0]*(?:\d+\$)?[s\[]", bounded))


def identifier_set(text: str) -> set[str]:
    return set(re.findall(r"\b[A-Za-z_]\w*\b", text))


def is_bounds_check(line: str, variables: set[str]) -> bool:
    if not re.search(r"\bif\s*\(", line) or "strlen" not in line or "sizeof" not in line:
        return False
    if not re.search(r"<=|<|>=|>", line):
        return False
    return len(identifier_set(line) & variables) >= 2


def mitigation_names(filters: list[str] | tuple[str, ...] | None = None) -> set[str]:
    names = set(MITIGATION_CALLS)
    for item in filters or []:
        token = item.strip()
        if token.lower() in OBSERVATION_ONLY_FILTERS or not re.fullmatch(r"[A-Za-z_]\w*", token):
            continue
        names.add(token)
    return names


def mitigation_on_line(line: str, variables: set[str], filters: list[str] | tuple[str, ...] | None = None) -> str | None:
    identifiers = identifier_set(line)
    for name in mitigation_names(filters):
        if re.search(rf"\b{re.escape(name)}\s*\(", line) and (not variables or bool(variables & identifiers)):
            return name
    if is_bounds_check(line, variables):
        return "bounds_check"
    return None
