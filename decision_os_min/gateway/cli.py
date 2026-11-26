"""`decision-os`: one command to put Decision OS in front of your agents.

decision-os install              wrap every MCP server in every detected app
decision-os run -- claude        start an agent behind the model gateway
decision-os ui                   approvals and live activity in the browser
decision-os status | audit | policy | approve | doctor | uninstall
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .paths import Home, write_private


def _home(args: argparse.Namespace) -> Home:
    return Home.resolve(args.home)


def _short(p: Path) -> str:
    try:
        return "~/" + str(p.relative_to(Path.home())).replace("\\", "/")
    except ValueError:
        return str(p)


def _names(xs: list[str]) -> str:
    return ", ".join(xs[:6]) + (f" +{len(xs) - 6}" if len(xs) > 6 else "")


# ----------------------------------------------------------------- init


def init_home(home: Home, *, profile: str, mode: str, reset_policy: bool = False) -> list[str]:
    from ..kernel import load_or_create_signing_key
    from .approvals import dashboard_token
    from .policy import default_policy_text

    notes = []
    home.ensure()
    if reset_policy or not home.policy.exists():
        write_private(home.policy, default_policy_text(profile, mode))
        notes.append(f"policy written: {_short(home.policy)} (profile {profile}, mode {mode})")
    else:
        notes.append(f"policy kept: {_short(home.policy)} (use --reset-policy to rewrite it)")
    load_or_create_signing_key(str(home.key))
    dashboard_token(home)
    return notes


# ----------------------------------------------------------------- commands


def cmd_install(args: argparse.Namespace) -> int:
    from . import clients, installer

    home = _home(args)
    mode = "observe" if args.observe else "enforce"
    if args.dry_run:
        print("  dry run: nothing is written")
    else:
        for note in init_home(
            home, profile=args.profile, mode=mode, reset_policy=args.reset_policy
        ):
            print(f"  {note}")
    project = Path(args.project).resolve() if args.project else None
    reports = installer.run(
        home,
        "install",
        clients=args.client or None,
        project=project,
        dry_run=args.dry_run,
        force_jsonc=args.force_jsonc,
    )
    total, apps, hints = 0, set(), []
    print()
    for r in reports:
        if r.status == "missing":
            continue
        spec = clients.get(r.client)
        parts = []
        if r.wrapped:
            parts.append(f"governed now: {_names(r.wrapped)}")
        if r.already:
            parts.append(f"already governed: {_names(r.already)}")
        if r.remote:
            parts.append(f"remote, left as is: {_names(r.remote)}")
        if r.plain:
            parts.append(f"NOT governed: {_names(r.plain)}")
        if r.message:
            parts.append(r.message)
        if not parts:
            parts.append("no MCP servers configured")
        print(f"  {spec.name:<20} {_short(r.path)}")
        print(
            f"  {'':<20} {'; '.join(parts)}"
            + (f"  [{r.status}]" if r.status not in ("ok", "unchanged") else "")
        )
        n = len(r.wrapped) + len(r.already)
        if n:
            total += n
            apps.add(spec.name)
        if r.wrapped and spec.restart_hint:
            hints.append(f"{spec.name}: {spec.restart_hint}")
    print()
    verb = "would govern" if args.dry_run else "governs"
    print(f"Decision OS {verb} {total} MCP server(s) across {len(apps)} app(s).")
    if not args.dry_run:
        for h in sorted(set(hints)):
            print(f"  then: {h}")
        print("\nNext:")
        print("  decision-os ui                 approvals and live activity")
        print(
            "  decision-os run -- <agent>     also gate an agent's built-in tools via its model API"
        )
        print("  decision-os uninstall          restore every config exactly")
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    from . import clients, installer

    home = _home(args)
    project = Path(args.project).resolve() if args.project else None
    reports = installer.run(
        home,
        "uninstall",
        clients=args.client or None,
        project=project,
        dry_run=args.dry_run,
        force_jsonc=args.force_jsonc,
    )
    n = 0
    for r in reports:
        if r.unwrapped or r.message:
            print(
                f"  {clients.get(r.client).name:<20} {_short(r.path)}: "
                f"restored {_names(r.unwrapped) or '-'} {r.message}"
            )
            n += len(r.unwrapped)
    print(f"Restored {n} MCP server(s). Your policy and audit log are kept in {_short(home.root)}.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from . import clients, installer
    from .policy import PolicyError, load_policy

    home = _home(args)
    try:
        p = load_policy(home.policy)
        summary = f"mode {p.mode}, profile {p.profile}, {len(p.rules)} rule(s)"
        print(f"policy   {_short(home.policy)}: {summary}")
    except PolicyError as exc:
        print(f"policy   ERROR: {exc}")
    project = Path(args.project).resolve() if args.project else None
    for r in installer.run(home, "status", project=project):
        if r.status == "missing":
            continue
        name = clients.get(r.client).name
        print(
            f"{name:<20} governed {len(r.already):>2}  ungoverned {len(r.plain):>2}  "
            f"remote {len(r.remote):>2}   {_short(r.path)}"
        )
        if r.plain:
            print(f"{'':<20} ungoverned: {_names(r.plain)}  (run decision-os install)")
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    from .policy import PolicyError, load_policy
    from .ui import serve

    home = _home(args)
    port = args.port
    if port is None:
        try:
            port = load_policy(home.policy).dashboard_port
        except PolicyError:
            port = 8766
    serve(home, port, open_browser=not args.no_browser)
    return 0


def cmd_mcp_proxy(args: argparse.Namespace) -> int:
    from .engine import Gateway
    from .mcp_proxy import run

    argv = list(args.command)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        sys.stderr.write("decision-os mcp-proxy: give the server command after --\n")
        return 2
    gw = Gateway(client=args.client, home=_home(args))
    return run(gw, args.server, argv)


def _upstreams(specs: list[str]) -> dict[str, str]:
    from .llm_proxy import parse_upstream_override

    return dict(parse_upstream_override(s) for s in specs or [])


def cmd_llm(args: argparse.Namespace) -> int:
    from .llm_proxy import LlmGateway

    gw = LlmGateway(_home(args), agent=args.agent, upstreams=_upstreams(args.upstream))
    srv = gw.serve(args.host, args.port)
    base = f"http://{args.host}:{srv.server_address[1]}"
    print(f"Decision OS model gateway on {base}")
    print(f"  OpenAI-compatible: {base}/u/openai   Anthropic: {base}/u/anthropic")
    print(f"  any other upstream from the policy: {base}/u/<name>")
    print("  Tell the gateway who is calling with the X-Decision-OS-Agent header (optional).")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from .llm_proxy import LlmGateway, agent_env

    argv = list(args.command)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        sys.stderr.write("usage: decision-os run [--agent NAME] -- <agent command>\n")
        return 2
    agent = args.agent or Path(argv[0]).stem
    home = _home(args)
    if not home.policy.exists():
        init_home(home, profile="balanced", mode="enforce")
    env, implied = agent_env(0, env=dict(os.environ), agent=agent)  # discover user overrides
    ups = {**implied, **_upstreams(args.upstream)}
    gw = LlmGateway(home, agent=agent, upstreams=ups)
    port = gw.serve_in_thread()
    env, _ = agent_env(port, env=dict(os.environ), agent=agent)
    sys.stderr.write(f"decision-os: {agent} runs behind the model gateway on 127.0.0.1:{port}\n")
    exe = shutil.which(argv[0]) or argv[0]
    try:
        return subprocess.call([exe, *argv[1:]], env=env)
    except FileNotFoundError:
        sys.stderr.write(f"decision-os: command not found: {argv[0]}\n")
        return 127
    except KeyboardInterrupt:
        return 130


def cmd_audit(args: argparse.Namespace) -> int:
    from .audit import LockedHashLog

    home = _home(args)
    if not home.audit.exists():
        print("no audit log yet")
        return 0
    log = LockedHashLog(home.audit, home.locks / "audit.lock")
    if args.verify:
        ok = log.verify()
        seq, head = log.head()
        print(f"chain {'verified' if ok else 'BROKEN'}: {seq + 1} entries, head {head[:16]}…")
        return 0 if ok else 1
    entries = log.tail(args.tail)
    if args.json:
        for e in entries:
            print(json.dumps(e))
        return 0
    if args.summary:
        from collections import Counter

        c = Counter((e["verdict"], bool(e.get("executed"))) for e in log.entries())
        reasons = [str(e.get("reason", "")) for e in log.entries()]
        would = Counter(
            k
            for r in reasons
            if r.startswith("observe:")
            for k in ("deny", "ask")
            if f"would {k}" in r
        )
        for (v, ran), n in sorted(c.items()):
            print(f"{v:<8} {'ran' if ran else 'refused':<8} {n}")
        if would:
            print("observe mode, would have:", ", ".join(f"{k} {n}" for k, n in would.items()))
        return 0
    for e in entries:
        outcome = "ran" if e.get("executed") else "refused"
        print(
            f"{e['ts'][:19]}  {e['actor'].removeprefix('agent:'):<14} {e['tool']:<32} "
            f"{e['verdict']:<7} {outcome:<7} {e['reason']}"
        )
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    from .engine import self_protected_paths, slug
    from .guardrails import Guardrails
    from .policy import PolicyError, evaluate, load_policy

    home = _home(args)
    if args.action == "path":
        print(home.policy)
        return 0
    try:
        policy = load_policy(home.policy)
    except PolicyError as exc:
        print(f"invalid: {exc}")
        return 1
    if args.action == "check":
        print(
            f"ok: mode {policy.mode}, profile {policy.profile}, {len(policy.rules)} rule(s), "
            f"revision {policy.revision}"
        )
        return 0
    if args.action == "show":
        print(home.policy.read_text(encoding="utf-8"))
        return 0
    # explain
    if not (args.server and args.tool):
        print("usage: decision-os policy explain --server S --tool T [--client C] [--args JSON]")
        return 2
    from .approvals import LearnedStore

    call_args = json.loads(args.args) if args.args else {}
    m = evaluate(
        policy,
        client=slug(args.client),
        server=slug(args.server),
        tool=args.tool,
        model=args.model,
        args=call_args,
        learned=LearnedStore(home).load(),
    )
    print(f"policy:     {m.decision}  ({m.reason})")
    g = Guardrails(policy.guardrails, self_paths=self_protected_paths(home)).scan(
        args.tool, call_args
    )
    for f in g:
        print(f"guardrail:  {f.level}  ({f.message})")
    if not g:
        print("guardrail:  clean")
    order = {"allow": 0, "ask": 1, "deny": 2}
    final = max([m.decision, *(f.level for f in g)], key=lambda d: order[d])
    if policy.mode == "observe":
        print(f"result:     would {final}, but observe mode runs it")
    else:
        print(f"result:     {final}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    from .approvals import APPROVED, DENIED, ApprovalStore

    store = ApprovalStore(_home(args))
    pending = store.pending()
    if not pending:
        print("nothing is waiting")
        return 0
    for r in pending:
        print(f"\n{r['client']} wants {r['server']}/{r['tool']}")
        print(f"  why:  {r.get('reason', '')}")
        print(f"  args: {r.get('arguments_preview', '')[:800]}")
        opts = (
            "[a]llow once, [A]lways allow, [d]eny, [s]kip"
            if r.get("rememberable")
            else "[a]llow once, [d]eny, [s]kip"
        )
        try:
            ans = input(f"  {opts}: ").strip()
        except EOFError:
            return 0
        if ans in ("a", "A"):
            store.resolve(r["id"], APPROVED, by="cli", remember=(ans == "A"))
        elif ans in ("d", "D"):
            store.resolve(r["id"], DENIED, by="cli", remember=(ans == "D"))
    return 0


def cmd_observe(args: argparse.Namespace) -> int:
    from .ui import Dashboard

    mode = "observe" if args.state == "on" else "enforce"
    Dashboard(_home(args)).set_mode(mode)
    print(f"mode is now {mode}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from . import installer
    from .audit import LockedHashLog
    from .policy import PolicyError, load_policy

    home = _home(args)
    ok = True

    def line(good: bool, text: str) -> None:
        nonlocal ok
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'}  {text}")

    line(sys.version_info >= (3, 11), f"python {sys.version.split()[0]} at {sys.executable}")
    line(home.root.exists(), f"home {home.root}")
    try:
        p = load_policy(home.policy)
        line(True, f"policy valid (mode {p.mode}, profile {p.profile})")
    except PolicyError as exc:
        line(False, f"policy: {exc}")
    line(home.key.exists(), f"kernel key {home.key}")
    if home.audit.exists():
        line(LockedHashLog(home.audit, home.locks / "audit.lock").verify(), "audit chain verifies")
    state = installer.State(home)
    for k, rec in state.data.get("entries", {}).items():
        path, _, name = json.loads(k)
        cmd = (rec.get("original") or {}).get("command", "")
        found = bool(shutil.which(cmd)) or Path(cmd).exists()
        line(
            found,
            f"{rec.get('client')}/{name}: upstream command '{cmd}' "
            f"{'found' if found else 'not found on PATH'}",
        )
    py = state.data.get("python")
    if py:
        line(Path(py).exists(), f"wrapped configs use {py}")
    return 0 if ok else 1


# ----------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    from .clients import CLIENT_IDS

    ap = argparse.ArgumentParser(
        prog="decision-os",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--home", help="state directory (default ~/.decision-os or $DECISION_OS_HOME)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("install", help="govern every MCP server of every detected app")
    s.add_argument("--profile", choices=["balanced", "strict", "open"], default="balanced")
    s.add_argument("--observe", action="store_true", help="record what would happen, block nothing")
    s.add_argument(
        "--client", action="append", choices=CLIENT_IDS, help="only these apps (repeatable)"
    )
    s.add_argument(
        "--project", help="wrap a project's own configs (.mcp.json, .cursor/, .vscode/ ...)"
    )
    s.add_argument("--dry-run", action="store_true")
    s.add_argument(
        "--force-jsonc", action="store_true", help="rewrite JSON files that contain comments"
    )
    s.add_argument("--reset-policy", action="store_true")
    s.set_defaults(fn=cmd_install)

    s = sub.add_parser("uninstall", help="restore every wrapped config")
    s.add_argument("--client", action="append", choices=CLIENT_IDS)
    s.add_argument("--project")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--force-jsonc", action="store_true")
    s.set_defaults(fn=cmd_uninstall)

    s = sub.add_parser("status", help="what is governed")
    s.add_argument("--project")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("ui", help="open the approval dashboard")
    s.add_argument("--port", type=int)
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(fn=cmd_ui)

    s = sub.add_parser("approve", help="answer pending approvals in the terminal")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("audit", help="show or verify the audit log")
    s.add_argument("--tail", type=int, default=30)
    s.add_argument("--verify", action="store_true")
    s.add_argument("--json", action="store_true")
    s.add_argument("--summary", action="store_true")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("policy", help="path | check | show | explain")
    s.add_argument("action", choices=["path", "check", "show", "explain"])
    s.add_argument("--client", default="cli")
    s.add_argument("--server")
    s.add_argument("--tool")
    s.add_argument("--model")
    s.add_argument("--args", help="tool arguments as JSON")
    s.set_defaults(fn=cmd_policy)

    s = sub.add_parser("observe", help="observe on|off: record only, or enforce")
    s.add_argument("state", choices=["on", "off"])
    s.set_defaults(fn=cmd_observe)

    s = sub.add_parser("run", help="run an agent behind the model gateway")
    s.add_argument("--agent", help="name used in rules and the audit log (default: command name)")
    s.add_argument("--upstream", action="append", help="name=https://host/base (repeatable)")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("llm", help="serve the model gateway")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--agent", default="llm-client")
    s.add_argument("--upstream", action="append")
    s.set_defaults(fn=cmd_llm)

    s = sub.add_parser("mcp-proxy", help=argparse.SUPPRESS)
    s.add_argument("--client", required=True)
    s.add_argument("--server", required=True)
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_mcp_proxy)

    s = sub.add_parser("doctor", help="check the installation")
    s.set_defaults(fn=cmd_doctor)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args) or 0)
