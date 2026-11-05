"""Build scanner argument lists from an allowlist of flags. Never uses a shell."""

from __future__ import annotations

import re

from app.scope.models import Decision

NMAP_FLAGS_WITHOUT_VALUE = frozenset({"-sV", "-sT", "-Pn", "-T2", "-T3"})
NMAP_OUTPUT_FLAGS = frozenset({"-oX"})
ALLOWED_NSE_CATEGORIES = frozenset({"default", "safe", "discovery", "version"})
REJECTED_NSE_TOKENS = frozenset({"brute", "dos", "intrusive", "exploit", "fuzzer", "vuln"})
_PORT_SPEC = re.compile(r"^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$")
_OUTPUT_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class ArgsSanitizerError(ValueError):
    """Raised when caller-supplied flags cannot be represented as a safe argv list."""


def sanitize_args(tool: str, args: list[str]) -> list[str]:
    """Return a validated argv list, or raise ArgsSanitizerError."""
    if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
        raise ArgsSanitizerError("args must be a list of strings, never a shell command")
    if any("\x00" in item or "\n" in item or "\r" in item for item in args):
        raise ArgsSanitizerError("args contain control characters")
    normalized = tool.strip().lower()
    if normalized == "nmap":
        return sanitize_nmap_args(args)
    raise ArgsSanitizerError(f"no argument allowlist is registered for tool {tool}")


def sanitize_nmap_args(args: list[str]) -> list[str]:
    """Allow only the documented Nmap discovery flags as an argument list."""
    sanitized: list[str] = []
    index = 0
    while index < len(args):
        flag = args[index]
        if flag in NMAP_FLAGS_WITHOUT_VALUE:
            sanitized.append(flag)
            index += 1
            continue
        if flag == "-p":
            if index + 1 >= len(args) or not _PORT_SPEC.fullmatch(args[index + 1]):
                raise ArgsSanitizerError("nmap -p requires an explicit numeric port list")
            sanitized.extend(["-p", args[index + 1]])
            index += 2
            continue
        if flag == "--top-ports":
            if index + 1 >= len(args) or not args[index + 1].isdigit():
                raise ArgsSanitizerError("nmap --top-ports requires a positive integer")
            count = int(args[index + 1])
            if count < 1 or count > 1000:
                raise ArgsSanitizerError("nmap --top-ports is out of the allowed range")
            sanitized.extend(["--top-ports", args[index + 1]])
            index += 2
            continue
        if flag in NMAP_OUTPUT_FLAGS:
            if index + 1 >= len(args) or not _OUTPUT_NAME.fullmatch(args[index + 1]):
                raise ArgsSanitizerError("nmap -oX requires a simple relative filename")
            sanitized.extend([flag, args[index + 1]])
            index += 2
            continue
        if flag in {"--script", "--script-categories"}:
            if index + 1 >= len(args):
                raise ArgsSanitizerError("nmap script flag requires an explicit category list")
            categories = [
                item.strip().lower() for item in args[index + 1].split(",") if item.strip()
            ]
            if not categories:
                raise ArgsSanitizerError("nmap script categories must not be empty")
            blocked = [item for item in categories if item in REJECTED_NSE_TOKENS]
            if blocked:
                raise ArgsSanitizerError(f"nmap NSE category {blocked[0]} is rejected by default")
            unknown = [item for item in categories if item not in ALLOWED_NSE_CATEGORIES]
            if unknown:
                raise ArgsSanitizerError(f"nmap NSE category {unknown[0]} is not allowlisted")
            sanitized.extend(["--script", ",".join(categories)])
            index += 2
            continue
        raise ArgsSanitizerError(f"nmap flag {flag} is not allowlisted")
    return sanitized


def decision_for_args(tool: str, args: list[str]) -> Decision:
    """Translate sanitizer success or failure into a scope Decision."""
    try:
        sanitize_args(tool, args)
    except ArgsSanitizerError as exc:
        return Decision.deny(str(exc), rule_id="args-allowlist")
    return Decision.allow("args are within the tool allowlist", rule_id="args-allowlist")
