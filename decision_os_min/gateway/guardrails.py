"""The guardrail pack: deterministic checks run on every call as a veto.

This is the *legitimacy* side of the Decision OS split ("should this happen at
all?"), packaged as an ``Evaluator``. It can only tighten a verdict: it returns
``ALLOW`` (which grants nothing on its own), ``DEFER`` (a human must approve this
exact action) or ``DENY``. No ML, no network, no heuristics that change between
runs: the same arguments always produce the same findings.

Self-protection is not configurable. A governed tool call may never touch the
gateway's own directory or an MCP client config, because that is how an agent
would approve itself or unwrap the gateway.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..compose import ALLOW, DEFER, DENY
from ..kernel import action_fingerprint
from .policy import GuardrailConfig, _is_pathlike, normalize_path, tool_tokens

# ---------------------------------------------------------------- patterns

PROTECTED_PATHS = (
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.config/gcloud",
    "~/.azure",
    "~/.kube",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.git-credentials",
    "~/.config/gh",
    "~/.terraform.d/credentials.tfrc.json",
    "~/.vault-token",
    "~/Library/Keychains",
    "~/.password-store",
    "~/.config/op",
    "/etc/shadow",
    "/etc/sudoers",
)
SECRET_FILE_NAMES = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "id_rsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "id_dsa*",
    "*.kdbx",
    "credentials",
    "credentials.json",
    "service-account*.json",
    "secrets.yaml",
    "secrets.yml",
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx))
    for name, rx in (
        ("private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
        ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
        ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{32,}"),
        ("OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}"),
        ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
        ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
        ("Stripe live key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
        ("Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b"),
    )
)

_RX = re.IGNORECASE | re.MULTILINE
CATASTROPHIC: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx, _RX))
    for name, rx in (
        (
            "recursive delete of / or home",
            r"\brm\s+(?:-[a-z]*\s+)*-[a-z]*(?:rf|fr)[a-z]*\s+(?:-[a-z-]+\s+)*"
            r"(?:/|/\*|~|~/|~/\*|\$HOME|\$\{HOME\}|\*)(?=[\s;&|)]|$)",
        ),
        ("filesystem format", r"\bmkfs(?:\.[a-z0-9]+)?\b|\bwipefs\b"),
        (
            "raw write to a disk",
            r"\bdd\b[^\n]*\bof=/dev/(?:sd|hd|nvme|disk|mmcblk|xvd|vd)"
            r"|>\s*/dev/(?:sd|nvme|disk|mmcblk)[a-z0-9]*\b",
        ),
        ("fork bomb", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        ("world-writable root", r"\bchmod\s+(?:-R\s+)?0?777\s+/(?=\s|$)"),
        ("Windows drive format", r"\bformat(?:\.com)?\s+[a-z]:"),
        (
            "Windows drive delete",
            r"\b(?:rd|rmdir)\s+/s\s+(?:/q\s+)?[a-z]:\\?(?=\s|$)"
            r"|\bRemove-Item\b[^\n]*-Recurse[^\n]*\s[a-z]:\\?\*?(?=[\s\"']|$)",
        ),
    )
)
RISKY: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx, _RX))
    for name, rx in (
        (
            "download piped into a shell",
            r"\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|iex|Invoke-Expression)\b",
        ),
        ("force push", r"\bgit\s+push\b[^\n]*(?:\s--force(?:-with-lease)?\b|\s-f\b)"),
        ("history rewrite", r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f)"),
        (
            "recursive delete",
            r"\brm\s+(?:-[a-z]*\s+)*-[a-z]*(?:rf|fr)\b"
            r"|\bRemove-Item\b[^\n]*-Recurse",
        ),
        (
            "destructive SQL",
            r"\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b"
            r"|\bDELETE\s+FROM\s+[\w.\"`\[\]]+\s*(?:;|$)",
        ),
        ("privilege escalation", r"(?:^|[\s;&|(])sudo\s"),
        ("power state", r"\b(?:shutdown|reboot|poweroff|halt)\b(?:\s|$)"),
        (
            "infrastructure teardown",
            r"\bterraform\s+destroy\b|\bkubectl\s+delete\b"
            r"|\bhelm\s+uninstall\b|\bdocker\s+system\s+prune\b"
            r"|\baws\s+s3\s+rm\b[^\n]*--recursive",
        ),
        (
            "package publish",
            r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b",
        ),
    )
)

COMMAND_KEYS = frozenset(
    """
    command cmd commands script code shell bash sh powershell pwsh input query sql
    statement program args argv line exec run
""".split()
)
EXEC_TOKENS = frozenset(
    """
    exec execute run shell bash sh cmd command terminal powershell pwsh script eval
    sql query process spawn
""".split()
)
PATH_KEYS = frozenset(
    """
    path paths file files filename filepath file_path dir directory folder source
    destination dest target src dst cwd root uri location
""".split()
)


@dataclass(frozen=True)
class Finding:
    check: str  # protected_paths | secret_files | secrets_in_arguments | ...
    level: str  # deny | ask
    message: str


def _strings(value: Any, key: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, str(k).lower())
    elif isinstance(value, (list, tuple)):
        items = list(value)
        if items and all(isinstance(x, str) for x in items):
            yield key, " ".join(items)  # argv arrays such as ["bash", "-lc", "rm -rf /"]
        for x in items:
            yield from _strings(x, key)


def redact_secrets(text: str) -> str:
    for name, rx in SECRET_PATTERNS:
        text = rx.sub(f"[{name}]", text)
    return text


_TOKEN_SPLIT = re.compile(r"""[\s"'`=,;|&<>()]+""")


class Guardrails:
    def __init__(self, config: GuardrailConfig, *, self_paths: list[Path]) -> None:
        self.config = config
        self._self = [normalize_path(str(p)) for p in self_paths]
        self._protected = [
            normalize_path(p) for p in PROTECTED_PATHS + config.extra_protected_paths
        ]

    # ---- path checks
    @staticmethod
    def _under(path: str, roots: list[str]) -> str | None:
        for root in roots:
            if path == root or path.startswith(root.rstrip("/") + "/"):
                return root
        return None

    def _path_findings(self, candidate: str) -> Iterator[Finding]:
        p = normalize_path(candidate)
        hit = self._under(p, self._self)
        if hit:
            yield Finding(
                "self_protection",
                "deny",
                "touches Decision OS state or an MCP client config (self-protection)",
            )
            return
        level = self.config.level("protected_paths")
        if level != "off":
            hit = self._under(p, self._protected)
            if hit:
                yield Finding("protected_paths", level, f"touches protected credentials path {hit}")
                return
        level = self.config.level("secret_files")
        if level != "off":
            base = p.rsplit("/", 1)[-1].lower()
            for pat in SECRET_FILE_NAMES:
                if fnmatch.fnmatchcase(base, pat):
                    if base in (".env.example", ".env.sample", ".env.template"):
                        break
                    yield Finding("secret_files", level, f"touches a secret file ({base})")
                    return

    def scan(self, tool: str, args: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        def add(f: Finding) -> None:
            if (f.check, f.message) not in seen:
                seen.add((f.check, f.message))
                findings.append(f)

        exec_tool = bool(EXEC_TOKENS & set(tool_tokens(tool)))
        secrets_level = self.config.level("secrets_in_arguments")
        for key, text in _strings(args):
            if secrets_level != "off":
                for name, rx in SECRET_PATTERNS:
                    if rx.search(text):
                        add(
                            Finding(
                                "secrets_in_arguments",
                                secrets_level,
                                f"argument '{key or 'value'}' contains a {name}",
                            )
                        )
            # Paths: a path-valued argument, and path-looking tokens inside a
            # command. Free text (file contents, messages) is not tokenized, so a
            # README that mentions ~/.ssh is not mistaken for an access.
            commandish = exec_tool or key in COMMAND_KEYS
            candidates = []
            if key in PATH_KEYS or _is_pathlike(text):
                candidates.append(text)
            if commandish and len(text) < 20000:
                candidates += [t for t in _TOKEN_SPLIT.split(text) if t and _is_pathlike(t)]
            for c in candidates:
                for f in self._path_findings(c):
                    add(f)
            if commandish:
                for check, table in (
                    ("catastrophic_commands", CATASTROPHIC),
                    ("risky_commands", RISKY),
                ):
                    level = self.config.level(check)
                    if level == "off":
                        continue
                    for name, rx in table:
                        if rx.search(text):
                            add(Finding(check, level, f"{name} in '{key or 'command'}'"))
        return findings

    def evaluator(
        self,
        *,
        observe: Callable[[], bool],
        approved: Callable[[str], bool],
    ) -> Callable[[dict[str, Any]], dict[str, Any]]:
        """Build the veto-only evaluator handed to ``Kernel.decide``."""

        def evaluate(action: dict[str, Any]) -> dict[str, Any]:
            tool = str(action.get("tool", "")).split("/", 1)[-1]
            findings = self.scan(tool, action.get("payload") or {})
            if not findings:
                return {"verdict": ALLOW, "reason": "guardrails: clean"}
            deny = [f for f in findings if f.level == "deny"]
            worst = deny or findings
            text = "; ".join(f.message for f in worst)
            if observe() and not any(f.check == "self_protection" for f in findings):
                kind = "deny" if deny else "ask"
                return {"verdict": ALLOW, "reason": f"observe: guardrail would {kind}: {text}"}
            if deny:
                return {"verdict": DENY, "reason": f"guardrail: {text}"}
            if approved(action_fingerprint(action)):
                return {"verdict": ALLOW, "reason": f"guardrail approved by you: {text}"}
            return {"verdict": DEFER, "reason": f"guardrail: {text}"}

        return evaluate
