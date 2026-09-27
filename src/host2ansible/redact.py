"""Replace secret-shaped values with Ansible placeholders.

Threats: generated playbooks are reviewed and often committed. Password-like
assignments, URI passwords, pgbouncer userlist entries, and PEM private-key
blocks are replaced. The investigation bundle can still hold original bytes
and is not a git artifact. This is a heuristic, not a complete secret scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PEM = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
    re.DOTALL,
)

_ASSIGN = re.compile(
    r"(?im)^(?P<prefix>[ \t]*[#;]*[ \t]*)"
    r"(?P<key>[A-Za-z0-9_.-]*"
    r"(?:password|passwd|secret|api[_-]?key|token|private[_-]?key|client[_-]?secret)"
    r"[A-Za-z0-9_.-]*)"
    r"(?P<sep>[ \t]*[:=][ \t]*)"
    r"(?:\"(?P<dq>[^\"\n]*)\"|'(?P<sq>[^'\n]*)'|(?P<bare>[^\s#]+))"
)

_URI = re.compile(r"(?i)(://[^/:@\s]+:)([^@\s/]+)(@)")

_USERLIST = re.compile(r'^(\s*"[^"]+"\s+")([^"]+)(")\s*$')

@dataclass(frozen=True)
class SecretHit:
    variable: str
    kind: str
    line: int
    path: str


def looks_like_private_key(prefix: bytes) -> bool:
    first = prefix.split(b"\n", 1)[0][:80]
    return b"PRIVATE KEY-----" in first


def redact_text(text: str, service: str, path: str, start: int = 1) -> tuple[str, list[SecretHit]]:
    """Return text with @@H2A{n}@@ tokens and the hits that name vault vars."""
    hits: list[SecretHit] = []
    index = start

    def token_for(kind: str, line: int) -> str:
        nonlocal index
        token = f"@@H2A{index}@@"
        if token in text:
            raise ValueError(f"refusing to redact; marker already present in {path}")
        hits.append(
            SecretHit(
                variable=f"h2a_secret_{service}_{index}",
                kind=kind,
                line=line,
                path=path,
            )
        )
        index += 1
        return token

    def line_of(offset: int) -> int:
        return text.count("\n", 0, offset) + 1

    def pem_sub(match: re.Match[str]) -> str:
        return token_for("private_key", line_of(match.start()))

    text = _PEM.sub(pem_sub, text)

    def uri_sub(match: re.Match[str]) -> str:
        return match.group(1) + token_for("uri_password", line_of(match.start())) + match.group(3)

    text = _URI.sub(uri_sub, text)

    if path.rsplit("/", 1)[-1] == "userlist.txt":

        def user_sub(match: re.Match[str]) -> str:
            return match.group(1) + token_for("userlist", line_of(match.start())) + match.group(3)

        text = "\n".join(user_sub(m) if (m := _USERLIST.match(line)) else line for line in text.split("\n"))

    def assign_sub(match: re.Match[str]) -> str:
        token = token_for("password", line_of(match.start()))
        if match.group("dq") is not None:
            value = f'"{token}"'
        elif match.group("sq") is not None:
            value = f"'{token}'"
        else:
            value = token
        return f"{match.group('prefix')}{match.group('key')}{match.group('sep')}{value}"

    text = _ASSIGN.sub(assign_sub, text)
    return text, hits


def to_template(tokenized: str, hits: list[SecretHit]) -> str:
    """Escape existing Jinja, then turn redact tokens into vault variables."""
    escaped = (
        tokenized.replace("{{", "{{ '{{' }}")
        .replace("{%", "{{ '{%' }}")
        .replace("{#", "{{ '{#' }}")
    )
    for number, hit in enumerate(hits, start=_first_index(hits)):
        escaped = escaped.replace(f"@@H2A{number}@@", "{{ " + hit.variable + " }}")
    return escaped


def _first_index(hits: list[SecretHit]) -> int:
    if not hits:
        return 1
    return int(hits[0].variable.rsplit("_", 1)[-1])
