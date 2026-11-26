"""The user-facing policy: a small TOML file of allow / ask / deny rules.

The file is compiled into a trusted ``AuthorityPDP`` (see ``engine.py``). It can
grant or refuse, but like every PDP it never sees the signing key, the spent
store or the effect: only the kernel turns its verdict into executable
authority.

Evaluation order for one tool call:

1. explicit ``[[rule]]`` entries, first match wins; a matching ``deny`` is final;
2. decisions the user remembered from the dashboard ("always allow / deny");
3. the explicit rule that matched, if it was ``allow`` or ``ask``;
4. the profile fallback (``balanced`` / ``strict`` / ``open``).

The guardrail pack (``guardrails.py``) is separate and runs as a veto-only
evaluator, so nothing in this file can switch it off for a single call.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import ntpath
import os
import posixpath
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DECISIONS = ("allow", "ask", "deny")
PROFILES = ("balanced", "strict", "open")
MODES = ("enforce", "observe")
GUARD_LEVELS = ("deny", "ask", "off")

DEFAULT_UPSTREAMS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "ollama": "http://localhost:11434/v1",
    "lmstudio": "http://localhost:1234/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "mistral": "https://api.mistral.ai/v1",
    "together": "https://api.together.xyz/v1",
    "xai": "https://api.x.ai/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
}

DEFAULT_GUARDRAILS: dict[str, str] = {
    "protected_paths": "deny",
    "secret_files": "ask",
    "secrets_in_arguments": "deny",
    "catastrophic_commands": "deny",
    "risky_commands": "ask",
}


class PolicyError(ValueError):
    """The policy file is missing, unreadable or invalid. The gateway fails closed."""


@dataclass(frozen=True)
class Rule:
    index: int
    decision: str
    client: str = "*"
    server: str = "*"
    tool: str = "*"
    model: str | None = None
    args: tuple[tuple[str, tuple[str, ...]], ...] = ()
    reason: str = ""
    redact: tuple[str, ...] = ()

    @property
    def purpose(self) -> str:
        return f"rule:{self.index}"

    def describe(self) -> str:
        parts = [
            f"{k}={v}"
            for k, v in (("client", self.client), ("server", self.server), ("tool", self.tool))
            if v != "*"
        ]
        if self.model:
            parts.append(f"model={self.model}")
        parts += [f"args.{k}={'|'.join(v)}" for k, v in self.args]
        return f"rule {self.index} ({', '.join(parts) or 'everything'})"


@dataclass(frozen=True)
class GuardrailConfig:
    enabled: bool = True
    levels: tuple[tuple[str, str], ...] = tuple(DEFAULT_GUARDRAILS.items())
    extra_protected_paths: tuple[str, ...] = ()

    def level(self, name: str) -> str:
        if not self.enabled:
            return "off"
        return dict(self.levels).get(name, DEFAULT_GUARDRAILS.get(name, "deny"))


@dataclass(frozen=True)
class GatewayPolicy:
    mode: str = "enforce"
    profile: str = "balanced"
    ask_timeout_seconds: float = 120.0
    hide_denied_tools: bool = True
    notify: bool = True
    open_dashboard: bool = True
    dashboard_port: int = 8766
    guardrails: GuardrailConfig = field(default_factory=GuardrailConfig)
    rules: tuple[Rule, ...] = ()
    upstreams: tuple[tuple[str, str], ...] = tuple(DEFAULT_UPSTREAMS.items())
    revision: str = "builtin"

    @property
    def upstream_map(self) -> dict[str, str]:
        return dict(self.upstreams)


@dataclass(frozen=True)
class Match:
    decision: str  # allow | ask | deny
    purpose: str  # bound into the action fingerprint
    reason: str
    redact: tuple[str, ...] = ()
    source: str = "policy"  # policy | learned | profile


# --------------------------------------------------------------------- loading

_TOP_KEYS = {
    "mode",
    "profile",
    "ask_timeout_seconds",
    "hide_denied_tools",
    "notify",
    "open_dashboard",
    "dashboard_port",
    "guardrails",
    "rule",
    "llm",
}
_RULE_KEYS = {"client", "server", "tool", "model", "args", "decision", "reason", "redact"}
_GUARD_KEYS = {"enabled", "extra_protected_paths", *DEFAULT_GUARDRAILS}


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise PolicyError(msg)


def parse_policy(text: str, *, source: str = "policy.toml") -> GatewayPolicy:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{source}: invalid TOML: {exc}") from exc
    unknown = set(data) - _TOP_KEYS
    _expect(not unknown, f"{source}: unknown setting(s) {sorted(unknown)}")

    mode = data.get("mode", "enforce")
    _expect(mode in MODES, f"{source}: mode must be one of {MODES}, got {mode!r}")
    profile = data.get("profile", "balanced")
    _expect(profile in PROFILES, f"{source}: profile must be one of {PROFILES}, got {profile!r}")
    timeout = data.get("ask_timeout_seconds", 120)
    _expect(
        isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and timeout > 0,
        f"{source}: ask_timeout_seconds must be a positive number",
    )
    port = data.get("dashboard_port", 8766)
    _expect(isinstance(port, int) and 0 < port < 65536, f"{source}: invalid dashboard_port")
    flags = {}
    for key in ("hide_denied_tools", "notify", "open_dashboard"):
        val = data.get(key, True)
        _expect(isinstance(val, bool), f"{source}: {key} must be true or false")
        flags[key] = val

    g = data.get("guardrails", {})
    _expect(isinstance(g, dict), f"{source}: [guardrails] must be a table")
    unknown = set(g) - _GUARD_KEYS
    _expect(not unknown, f"{source}: unknown guardrail setting(s) {sorted(unknown)}")
    enabled = g.get("enabled", True)
    _expect(isinstance(enabled, bool), f"{source}: guardrails.enabled must be true or false")
    levels = dict(DEFAULT_GUARDRAILS)
    for key in DEFAULT_GUARDRAILS:
        if key in g:
            _expect(
                g[key] in GUARD_LEVELS, f"{source}: guardrails.{key} must be one of {GUARD_LEVELS}"
            )
            levels[key] = g[key]
    extra = g.get("extra_protected_paths", [])
    _expect(
        isinstance(extra, list) and all(isinstance(x, str) for x in extra),
        f"{source}: guardrails.extra_protected_paths must be a list of strings",
    )

    rules = []
    raw_rules = data.get("rule", [])
    _expect(isinstance(raw_rules, list), f"{source}: use [[rule]] for rules")
    for i, r in enumerate(raw_rules, start=1):
        _expect(isinstance(r, dict), f"{source}: rule {i} must be a table")
        unknown = set(r) - _RULE_KEYS
        _expect(not unknown, f"{source}: rule {i} has unknown field(s) {sorted(unknown)}")
        decision = r.get("decision")
        _expect(decision in DECISIONS, f"{source}: rule {i} needs decision = allow | ask | deny")
        for key in ("client", "server", "tool", "model", "reason"):
            _expect(
                key not in r or isinstance(r[key], str),
                f"{source}: rule {i}: {key} must be a string",
            )
        args_raw = r.get("args", {})
        _expect(isinstance(args_raw, dict), f"{source}: rule {i}: args must be a table")
        args: list[tuple[str, tuple[str, ...]]] = []
        for name, pat in args_raw.items():
            pats = [pat] if isinstance(pat, str) else pat
            _expect(
                isinstance(pats, list) and bool(pats) and all(isinstance(p, str) for p in pats),
                f"{source}: rule {i}: args.{name} must be a glob or a list of globs",
            )
            args.append((name, tuple(pats)))
        redact = r.get("redact", [])
        _expect(
            isinstance(redact, list) and all(isinstance(x, str) for x in redact),
            f"{source}: rule {i}: redact must be a list of argument names",
        )
        _expect(
            not redact or decision != "deny", f"{source}: rule {i}: redact makes no sense on deny"
        )
        rules.append(
            Rule(
                index=i,
                decision=decision,
                client=r.get("client", "*"),
                server=r.get("server", "*"),
                tool=r.get("tool", "*"),
                model=r.get("model"),
                args=tuple(args),
                reason=r.get("reason", ""),
                redact=tuple(redact),
            )
        )

    upstreams = dict(DEFAULT_UPSTREAMS)
    llm = data.get("llm", {})
    _expect(isinstance(llm, dict), f"{source}: [llm] must be a table")
    _expect(set(llm) <= {"upstreams"}, f"{source}: [llm] only supports upstreams")
    for name, url in (llm.get("upstreams") or {}).items():
        _expect(
            isinstance(url, str) and re.match(r"^https?://", url) is not None,
            f"{source}: llm.upstreams.{name} must be an http(s) URL",
        )
        _expect(
            re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None,
            f"{source}: llm.upstreams name {name!r} may only use letters, digits, _ . -",
        )
        upstreams[name] = url.rstrip("/")

    return GatewayPolicy(
        mode=mode,
        profile=profile,
        ask_timeout_seconds=float(timeout),
        dashboard_port=port,
        guardrails=GuardrailConfig(enabled, tuple(levels.items()), tuple(extra)),
        rules=tuple(rules),
        upstreams=tuple(upstreams.items()),
        revision="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
        **flags,
    )


def load_policy(path: Path) -> GatewayPolicy:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PolicyError(f"no policy at {path}; run `decision-os install`") from exc
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc
    return parse_policy(text, source=str(path))


# ------------------------------------------------------------------- matching

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
READ_VERBS = frozenset(
    """
    read get list search find fetch view show describe inspect lookup look count stat
    head tail cat ls grep glob status info preview browse resolve explain query
    snapshot screenshot diff log logs check validate summarize summary download
    retrieve load open recall
""".split()
)
WRITE_VERBS = frozenset(
    """
    write create delete del remove rm rmdir unlink update edit set put post send push commit
    merge move mv rename copy cp upload install uninstall run exec execute eval shell bash
    sh cmd command terminal powershell kill start stop restart deploy publish apply drop
    truncate insert patch modify replace approve pay transfer buy purchase order book
    invite share grant revoke reset format wipe click type fill submit press drag
    navigate mkdir touch chmod chown save append archive close cancel reply forward
    schedule trigger invoke call spawn launch
""".split()
)


def tool_tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", _CAMEL.sub("_", name).lower()) if t]


def classify_tool(name: str, hints: tuple[str, ...] | list[str] = ()) -> str:
    """'read', 'write' or 'unknown'. Hints come from MCP tool annotations: they
    can make an unclassified name read-only or mark any tool destructive, but a
    write verb in the name always wins."""
    hints = tuple(h.lower() for h in hints)
    tokens = tool_tokens(name)
    if "hint:destructive" in hints or any(t in WRITE_VERBS for t in tokens):
        return "write"
    if any(t in READ_VERBS for t in tokens):
        return "read"
    if "hint:readonly" in hints:
        return "read"
    return "unknown"


def _is_pathlike(s: str) -> bool:
    return bool(s) and (
        s.startswith(("~", "/", "./", "../", "\\\\", "file://"))
        or re.match(r"^[A-Za-z]:[\\/]", s) is not None
    )


def normalize_path(s: str) -> str:
    """Expand ~ and env vars, collapse ``..``, unify separators. Not resolve():
    the target may not exist, and following symlinks here would be a TOCTOU
    illusion anyway (documented limitation)."""
    if s.startswith("file://"):
        s = s[len("file://") :]
    s = os.path.expandvars(os.path.expanduser(s))
    if re.match(r"^[A-Za-z]:[\\/]", s) or s.startswith("\\\\") or os.name == "nt":
        return ntpath.normcase(ntpath.normpath(s)).replace("\\", "/")
    return posixpath.normpath(s)


def _glob(value: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _arg_matches(value: Any, patterns: tuple[str, ...]) -> bool:
    if isinstance(value, str):
        text = value
    elif value is None or isinstance(value, (bool, int, float)):
        text = json.dumps(value)
    else:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    for pat in patterns:
        if _is_pathlike(pat) and isinstance(value, str):
            if fnmatch.fnmatchcase(normalize_path(text), normalize_path(pat)):
                return True
        elif _glob(text, pat):
            return True
    return False


def rule_matches(
    rule: Rule,
    *,
    client: str,
    server: str,
    tool: str,
    model: str | None,
    args: dict[str, Any] | None,
) -> bool:
    if not (_glob(client, rule.client) and _glob(server, rule.server) and _glob(tool, rule.tool)):
        return False
    if rule.model is not None and (model is None or not _glob(model, rule.model)):
        return False
    if rule.args:
        if args is None:  # static check (tools/list): argument rules cannot be decided
            return False
        for name, pats in rule.args:
            if name not in args or not _arg_matches(args[name], pats):
                return False
    return True


def learned_key(client: str, server: str, tool: str) -> str:
    return f"{client}|{server}|{tool}"


def evaluate(
    policy: GatewayPolicy,
    *,
    client: str,
    server: str,
    tool: str,
    model: str | None = None,
    args: dict[str, Any] | None = None,
    hints: tuple[str, ...] = (),
    learned: dict[str, str] | None = None,
) -> Match:
    """Rule a call. The returned ``purpose`` depends only on the policy file and
    the tool (never on remembered choices), because it is bound into the action
    fingerprint before the PDP re-evaluates; a remembered choice made while an
    approval is pending must not invalidate that action."""
    matched: Rule | None = None
    for rule in policy.rules:
        if rule_matches(rule, client=client, server=server, tool=tool, model=model, args=args):
            matched = rule
            break
    kind = classify_tool(tool, hints)
    profile_purpose = f"profile:{policy.profile}:{kind}"
    purpose = matched.purpose if matched is not None else profile_purpose
    if matched is not None and matched.decision == "deny":
        return Match("deny", purpose, matched.reason or f"denied by {matched.describe()}")
    if learned:
        for key in (learned_key(client, server, tool), learned_key("*", server, tool)):
            remembered = learned.get(key)
            if remembered in ("allow", "deny"):
                return Match(
                    remembered,
                    purpose,
                    f"you chose 'always {remembered}' for {server}/{tool}",
                    matched.redact if matched is not None else (),
                    source="learned",
                )
    if matched is not None:
        verb = "allowed" if matched.decision == "allow" else "needs approval"
        return Match(
            matched.decision,
            purpose,
            matched.reason or f"{verb} by {matched.describe()}",
            matched.redact,
        )
    if policy.profile == "open":
        decision = "allow"
    elif policy.profile == "strict":
        decision = "ask"
    else:
        decision = "allow" if kind == "read" else "ask"
    what = {"read": "read-only", "write": "state-changing", "unknown": "unclassified"}[kind]
    verb = "allows" if decision == "allow" else "asks for"
    return Match(
        decision, profile_purpose, f"{policy.profile} profile {verb} {what} tools", source="profile"
    )


# ---------------------------------------------------------------- templates


def default_policy_text(profile: str = "balanced", mode: str = "enforce") -> str:
    if profile not in PROFILES:
        raise PolicyError(f"profile must be one of {PROFILES}")
    if mode not in MODES:
        raise PolicyError(f"mode must be one of {MODES}")
    return f'''# Decision OS gateway policy.
# Changes apply on the next tool call; `decision-os policy check` validates this file.

mode = "{mode}"            # enforce | observe (record what would happen, block nothing)
profile = "{profile}"       # balanced: read-only tools run, everything else asks
                          # strict:   every tool call asks until you allow it
                          # open:     everything runs; guardrails and audit still apply
ask_timeout_seconds = 120 # an unanswered approval is refused after this long
hide_denied_tools = true  # hard-denied tools are removed from tools/list
notify = true             # desktop notification when a call needs approval
open_dashboard = true     # open the approval page in the browser when needed
dashboard_port = 8766

[guardrails]
# deterministic checks that run on every call as a veto; each is deny | ask | off
enabled = true
protected_paths = "deny"        # ~/.ssh, ~/.aws, ~/.gnupg, cloud and package credentials
secret_files = "ask"            # .env, *.pem, *.key, id_rsa ...
secrets_in_arguments = "deny"   # API keys, tokens and private keys inside arguments
catastrophic_commands = "deny"  # rm -rf /, mkfs, dd onto a disk, fork bombs, format C:
risky_commands = "ask"          # git push --force, DROP TABLE, curl | sh, sudo, terraform destroy
extra_protected_paths = []

# Rules: first match wins. Globs: * matches anything (including /).
# Fields: client, server, tool, model, args = {{ name = "glob" }}, decision, reason,
# redact = ["argument", ...] (the value is replaced before the tool sees it).
#
# Examples:
#
# [[rule]]
# server = "filesystem"
# tool = "write_file"
# args = {{ path = "~/projects/*" }}
# decision = "allow"
#
# [[rule]]
# tool = "*delete*"
# decision = "deny"
# reason = "nothing gets deleted by an agent"
#
# [[rule]]
# client = "claude-code"
# server = "llm"
# tool = "Bash"
# decision = "ask"

# Model gateway upstreams for `decision-os run` (OpenAI-compatible or Anthropic).
# [llm.upstreams]
# work = "https://my-gateway.example.com/v1"
'''
