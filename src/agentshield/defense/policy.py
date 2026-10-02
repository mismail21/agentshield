"""Provenance policy: sensitive tool arguments must come from trusted context.

This is the grounding-checker idea from grounded-vuln-triage, applied to
*actions* instead of report claims. In the triage project every value in the
report had to trace back to a source the tools actually returned. Here every
security-relevant argument of a side-effecting call (an email recipient, a URL
to fetch, a shell command, a file path to write) has to trace back to
something the *user* or the *deployer* supplied: the user's request, the
address book, an allowlisted domain. A value that only appears inside
untrusted tool output - i.e. the attacker suggested it - is blocked.

It needs no model and no training data, so it can't be talked out of a
decision, but it only covers the argument kinds it knows about.
"""

from __future__ import annotations

import re
import posixpath
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

SHELL_META = re.compile(r"[\n\r|;&`$<>]|\b(curl|wget|nc|ncat|ssh|scp|base64|bash|sh|python\s+-c|rm|chmod|eval)\b")


def _host_ok(host: str, domains: list[str]) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in domains)


def check_value(kind: str, value: Any, prompt: str, trusted: dict[str, list[str]]) -> str | None:
    """Return a reason string if ``value`` is not grounded in trusted context, else None."""
    if isinstance(value, list):
        for v in value:
            reason = check_value(kind, v, prompt, trusted)
            if reason:
                return reason
        return None
    v = str(value).strip()
    p = prompt.lower()
    if not v:
        return None
    if kind == "email":
        if v.lower() in p or v.lower() in [e.lower() for e in trusted.get("email", [])]:
            return None
        return f"recipient {v!r} is not in the user's request or address book"
    if kind == "url":
        if v.lower() in p:
            return None
        host = urlparse(v if "://" in v else "https://" + v).hostname or ""
        if _host_ok(host, trusted.get("url", [])):
            return None
        return f"domain {host!r} is not in the user's request or the allowed domains"
    if kind == "command":
        if v in prompt:
            return None
        if not SHELL_META.search(v) and any(v == c or v.startswith(c + " ") for c in trusted.get("command", [])):
            return None
        return f"command {v!r} was not requested by the user and is not on the safe-command list"
    if kind == "path":
        normalized = posixpath.normpath(v)
        if '..' in PurePosixPath(v).parts or normalized in ('.','/'):
            return f'path {v!r} is not an explicit file path without traversal'
        candidates = {v, normalized, './' + normalized}
        if any(re.search(r'(?<![\w./-])'+re.escape(candidate)+r'(?![\w./-])',prompt)
               for candidate in candidates):
            return None
        return f"writing to {v!r} was not requested by the user"
    return None
