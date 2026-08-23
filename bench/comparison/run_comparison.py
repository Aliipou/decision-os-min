"""Fair, scope-aware comparison against real OPA, Cedar, and MCP.

This is not a speed leaderboard. The only directly comparable result is whether
Decision OS, OPA, and Cedar agree on the same six allow/deny cases. Latency is
recorded only with an explicit boundary label after a discarded warmup.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from decision_os_min import Kernel, LegitimacyAuthorityPipeline, legitimacy
from decision_os_min.attenuation import AuthorityGraph
from decision_os_min.authority_pdp import (
    BuiltinAuthorityPDP,
    CedarCLIAuthorityPDP,
    OPAHTTPAuthorityPDP,
)
from decision_os_min.compose import meet

HERE = Path(__file__).resolve().parent
SCENARIOS = json.loads((HERE / "scenarios.json").read_text(encoding="utf-8"))
OPA_IMAGE = (
    "openpolicyagent/opa@"
    "sha256:04efa82e4b5d41f2d58645146ddb1df89a9a140a14e8f787ca73d986e3d84bc9"
)
CEDAR_VERSION = "4.12.0"
POLICY = {
    "grants": {
        "agent:support": ["tool:send_email"],
        "agent:finance": ["tool:issue_payout"],
        "agent:release": ["tool:deploy_release"],
    },
    "purpose_bindings": {
        "customer_support": ["support_reply"],
        "finance": ["refund"],
        "ops": ["production_change"],
    },
    "default": "deny",
}
POLICY_COMPARABLE = ("decision-os-min-policy", "opa", "cedar")
DECISION_OS_SCOPES = (
    "decision-os-min-policy",
    "decision-os-min-signed",
    "decision-os-min",
)


def _percentiles(samples: list[float], *, warmup: int) -> dict[str, float | int]:
    ordered = sorted(samples)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    median = statistics.median(ordered)
    return {
        "n": len(samples),
        "warmup_discarded_per_scenario": warmup,
        "median_us": round(median, 3),
        "p95_us": round(p95, 3),
        "median_ms": round(median / 1000, 3),
        "p95_ms": round(p95 / 1000, 3),
    }


def _docker() -> str:
    found = shutil.which("docker")
    if found:
        return found
    windows = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")
    if windows.is_file():
        return str(windows)
    raise RuntimeError("Docker CLI not found")


def _run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        **kwargs,
    )


def _dos_action(scenario: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "actor": scenario["actor"],
        "tool": scenario["tool"],
        "capability": scenario["capability"],
        "action_purpose": scenario["purpose"],
        "data_labels": [scenario["data_label"]],
        "payload": {"consent": scenario["consent"]},
        "nonce": f"{scenario['id']}-{index}-{uuid.uuid4().hex}",
    }


def _opa_input(scenario: dict[str, Any], _index: int) -> dict[str, Any]:
    return {
        "actor": scenario["actor"],
        "tool": scenario["tool"],
        "purpose": scenario["purpose"],
        "data_label": scenario["data_label"],
        "consent": scenario["consent"],
    }


def _cedar_action(scenario: dict[str, Any], _index: int) -> dict[str, Any]:
    return {
        "actor": scenario["actor"],
        "tool": scenario["tool"],
        "resource": "governed",
        "action_purpose": scenario["purpose"],
        "data_label": scenario["data_label"],
        "payload": {"consent": scenario["consent"]},
    }


def _measure(
    evaluate: Callable[[dict[str, Any]], str],
    make_action: Callable[[dict[str, Any], int], dict[str, Any]],
    *,
    iterations: int,
    warmup: int,
) -> tuple[list[dict[str, Any]], list[float]]:
    rows: list[dict[str, Any]] = []
    all_samples: list[float] = []
    for scenario in SCENARIOS:
        for index in range(warmup):
            evaluate(make_action(scenario, -(index + 1)))
        samples: list[float] = []
        actual = ""
        for index in range(iterations):
            action = make_action(scenario, index)
            started = time.perf_counter_ns()
            actual = evaluate(action)
            samples.append((time.perf_counter_ns() - started) / 1000)
        all_samples.extend(samples)
        rows.append(
            {
                "id": scenario["id"],
                "expected": scenario["expected"],
                "actual": actual,
                "match": actual == scenario["expected"],
            }
        )
    return rows, all_samples


def _decision_os_policy(iterations: int, warmup: int) -> dict[str, Any]:
    graph = AuthorityGraph()
    graph.set_root_grants(POLICY["grants"])
    pdp = BuiltinAuthorityPDP(
        POLICY["grants"],
        POLICY["purpose_bindings"],
        graph,
        default_deny=True,
    )
    legitimacy_eval = legitimacy(
        lambda action: (bool(action["payload"].get("consent")), "consent required")
    )

    def evaluate(action: dict[str, Any]) -> str:
        authority = pdp.evaluate(action).verdict
        extra = legitimacy_eval(action)
        extra_verdict = extra["verdict"] if isinstance(extra, dict) else extra
        return meet(authority, extra_verdict)

    rows, samples = _measure(
        evaluate, _dos_action, iterations=iterations, warmup=warmup
    )
    return {
        "implementation": "decision-os-min-policy",
        "version": "0.1.0",
        "comparable_policy_decision": True,
        "scope": (
            "in-process built-in authority + legitimacy meet only; "
            "no signature, token, PEP, effect, or audit"
        ),
        "conformance": rows,
        "timing": _percentiles(samples, warmup=warmup),
    }


def _decision_os_signed(iterations: int, warmup: int) -> dict[str, Any]:
    kernel = Kernel(POLICY)
    evaluators = [
        legitimacy(
            lambda action: (
                bool(action["payload"].get("consent")),
                "consent required",
            )
        )
    ]

    def evaluate(action: dict[str, Any]) -> str:
        return kernel.decide(action, evaluators=evaluators)["decision"]["verdict"]

    rows, samples = _measure(
        evaluate, _dos_action, iterations=iterations, warmup=warmup
    )
    return {
        "implementation": "decision-os-min-signed",
        "version": "0.1.0",
        "comparable_policy_decision": False,
        "scope": (
            "kernel.decide: policy composition + action bind + Ed25519 sign + "
            "one-time token mint; no PEP, effect, or audit"
        ),
        "conformance": rows,
        "timing": _percentiles(samples, warmup=warmup),
    }


def _decision_os_full(iterations: int, warmup: int) -> dict[str, Any]:
    tools = {
        "send_email": lambda payload: payload,
        "issue_payout": lambda payload: payload,
        "deploy_release": lambda payload: payload,
    }
    with tempfile.TemporaryDirectory() as tmp:
        runtime = LegitimacyAuthorityPipeline(
            POLICY,
            audit_path=str(Path(tmp) / "audit.jsonl"),
            legitimacy=lambda action: (
                bool(action["payload"].get("consent")),
                "consent required",
            ),
        )

        def evaluate(action: dict[str, Any]) -> str:
            return runtime.handle(action, tools).verdict

        rows, samples = _measure(
            evaluate, _dos_action, iterations=iterations, warmup=warmup
        )
    return {
        "implementation": "decision-os-min",
        "version": "0.1.0",
        "comparable_policy_decision": False,
        "scope": (
            "full product path: signed decision + one-time PEP + effect "
            "callback + audit append"
        ),
        "conformance": rows,
        "timing": _percentiles(samples, warmup=warmup),
    }


def _opa(iterations: int, warmup: int) -> dict[str, Any]:
    docker = _docker()
    name = f"decision-os-opa-{uuid.uuid4().hex[:10]}"
    policy_mount = f"{HERE / 'policy.rego'}:/policy.rego:ro"
    _run(
        [
            docker,
            "run",
            "--detach",
            "--rm",
            "--name",
            name,
            "-p",
            "127.0.0.1::8181",
            "-v",
            policy_mount,
            OPA_IMAGE,
            "run",
            "--server",
            "--addr=0.0.0.0:8181",
            "/policy.rego",
        ]
    )
    try:
        port = _run(
            [docker, "port", name, "8181/tcp"],
        ).stdout.strip().rsplit(":", 1)[-1]
        url = f"http://127.0.0.1:{port}/v1/data/decisionos/allow"
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except OSError:
                time.sleep(0.25)
        else:
            raise RuntimeError("OPA server did not become ready")

        provider = OPAHTTPAuthorityPDP(
            url,
            policy_revision="opa-image-pinned-digest",
            timeout_s=5,
            health_url=f"http://127.0.0.1:{port}/health",
        )

        def evaluate(action: dict[str, Any]) -> str:
            return provider.evaluate(action).verdict

        rows, samples = _measure(
            evaluate, _opa_input, iterations=iterations, warmup=warmup
        )
        version = _run([docker, "run", "--rm", OPA_IMAGE, "version"]).stdout.splitlines()[0]
        return {
            "implementation": "opa",
            "version": version.replace("Version:", "").strip(),
            "image": OPA_IMAGE,
            "comparable_policy_decision": True,
            "scope": (
                "warm HTTP authorization query against official OPA; "
                "no PEP, effect, token, or audit"
            ),
            "conformance": rows,
            "timing": _percentiles(samples, warmup=warmup),
        }
    finally:
        subprocess.run([docker, "rm", "-f", name], capture_output=True)


def _cedar(iterations: int, warmup: int, cedar_bin: str) -> dict[str, Any]:
    version_text = _run([cedar_bin, "--version"]).stdout.strip()
    _run(
        [
            cedar_bin,
            "validate",
            "--schema",
            str(HERE / "schema.cedarschema"),
            "--policies",
            str(HERE / "policy.cedar"),
        ]
    )
    provider = CedarCLIAuthorityPDP(
        cedar_bin,
        policies=HERE / "policy.cedar",
        entities=HERE / "entities.json",
        schema=HERE / "schema.cedarschema",
        policy_revision="cedar-policy-cli-v4.12.0",
        timeout_s=5,
        context_map={
            "consent": "payload.consent",
            "purpose": "action_purpose",
            "data_label": "data_label",
        },
    )

    def evaluate(action: dict[str, Any]) -> str:
        return provider.evaluate(action).verdict

    rows, samples = _measure(
        evaluate, _cedar_action, iterations=iterations, warmup=warmup
    )
    return {
        "implementation": "cedar",
        "version": version_text,
        "comparable_policy_decision": True,
        "scope": (
            "official Cedar CLI authorize subprocess per request "
            "(process spawn is in the measured cost; this is not the "
            "in-process cedar-policy library); no PEP, effect, token, or audit"
        ),
        "conformance": rows,
        "timing": _percentiles(samples, warmup=warmup),
    }


def _mcp(iterations: int, warmup: int) -> dict[str, Any]:
    mcp_dir = HERE / "mcp"
    if not (mcp_dir / "node_modules").is_dir():
        _run(["npm", "ci"], cwd=mcp_dir)
    env = os.environ.copy()
    env["COMPARISON_ITERATIONS"] = str(warmup + iterations)
    raw = _run(["node", "client.mjs"], cwd=mcp_dir, env=env, timeout=180)
    data = json.loads(raw.stdout.strip().splitlines()[-1])
    all_samples: list[float] = []
    rows = []
    for row in data["rows"]:
        samples = row.pop("samples_us")[warmup:]
        all_samples.extend(samples)
        rows.append(row)
    package = json.loads(
        (mcp_dir / "node_modules/@modelcontextprotocol/server/package.json").read_text()
    )
    return {
        "implementation": "official-mcp-typescript-sdk",
        "version": package["version"],
        "comparable_policy_decision": False,
        "scope": (
            "warm connected stdio tool round-trip and schema validation; "
            "MCP is a transport, not a legitimacy/authority engine, so it "
            "has no allow/deny verdict"
        ),
        "conformance": rows,
        "timing": _percentiles(all_samples, warmup=warmup),
    }


def _default_cedar() -> str:
    found = shutil.which("cedar")
    if found:
        return found
    candidate = (
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "decision-os-comparison"
        / "cedar"
        / ("cedar.exe" if os.name == "nt" else "cedar")
    )
    if candidate.is_file():
        return str(candidate)
    raise RuntimeError(
        f"Cedar CLI {CEDAR_VERSION} not found; run: "
        f"cargo install cedar-policy-cli --version {CEDAR_VERSION} --locked"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--cedar-bin")
    parser.add_argument(
        "--output", type=Path, default=HERE / "results" / "latest.json"
    )
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    if args.warmup < 0:
        parser.error("--warmup must be >= 0")

    results = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "methodology": {
            "scenario_count": len(SCENARIOS),
            "iterations_per_scenario": args.iterations,
            "warmup_per_scenario": args.warmup,
            "comparable_result": (
                "policy conformance for Decision OS built-in+legitimacy, "
                "OPA HTTP, and Cedar CLI on the same six cases"
            ),
            "latency_not_a_ranking": True,
            "native_schemas": {
                "decision-os-min": (
                    "actor, tool, capability, action_purpose, data_labels, "
                    "payload.consent"
                ),
                "opa": "actor, tool, purpose, data_label, consent",
                "cedar": "principal, action, resource, context.{consent,purpose,data_label}",
            },
            "host": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "processor": platform.processor(),
            },
            "warning": (
                "Do not rank systems by latency. Cedar's measured cost includes "
                "a fresh CLI process; OPA is a warm HTTP query; Decision OS "
                "policy-only is in-process. MCP is not a policy engine."
            ),
        },
        "systems": [
            _decision_os_policy(args.iterations, args.warmup),
            _opa(args.iterations, args.warmup),
            _cedar(args.iterations, args.warmup, args.cedar_bin or _default_cedar()),
            _decision_os_signed(args.iterations, args.warmup),
            _decision_os_full(args.iterations, args.warmup),
            _mcp(args.iterations, args.warmup),
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    by_name = {system["implementation"]: system for system in results["systems"]}
    conformant = all(
        row["match"]
        for name in (*POLICY_COMPARABLE, *DECISION_OS_SCOPES)
        for row in by_name[name]["conformance"]
    )
    transported = all(
        row["transported"] and row["handler_executed"]
        for row in by_name["official-mcp-typescript-sdk"]["conformance"]
    )
    print(json.dumps(results, indent=2))
    return 0 if conformant and transported else 1


if __name__ == "__main__":
    raise SystemExit(main())
