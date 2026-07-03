# Plugin API — the stable extension contract

The kernel stays small and fixed; capability grows in **plugins** around it. A
plugin is just a Python package that provides a function or object matching one of
the **seams** below. There is no plugin framework to learn, no registration
daemon — the same model as a good library (OPA, Envoy): a stable contract others
build against.

## The one rule every plugin obeys

> A plugin may **advise, adapt, or provide a backend**. It may **never decide,
> never mint a token, and never bypass the kernel.** Authority flows one way, down
> from the single signer (see [AUTHORITY_MODEL.md](AUTHORITY_MODEL.md),
> [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md) §10).

If a plugin could change what `(policy, action)` decides, it would be a second
authority — and that is precisely what this architecture forbids.

## Stable seams

### 1. Advisor — `Callable[[action], str | None]`  *(in-core, stable)*

The only seam wired into the core today. An advisor suggests a threat class; the
kernel consults it and decides.

```python
from decision_os_min import DecisionOS

def my_advisor(action: dict) -> str | None:
    return "malicious" if looks_bad(action) else None

dos.handle(action, tools, advisor=my_advisor)   # advice only — can only tighten
```

Guarantee: an advisor can only move a verdict *more* restrictive; it can never
author a verdict or loosen a DENY (`test_advisor_plugin_can_only_tighten`).
Reference plugin: **plugin-ml**, **plugin-quantum** (risk advisors).

### 2. Adapter seams  *(in plugins, stable shapes)*

These live in their own repos and produce inputs to the core; the core does not
import them.

| Seam | Signature | Role | Plugin |
|---|---|---|---|
| Signer (crypto-agility) | `sign(bytes)->bytes`, `public_key()->bytes` | swap Ed25519 for PQC/HSM | plugin-pqcrypto, plugin-tpm-hsm |
| Policy compiler | `compile(source)->policy_dict` | author policy in OPA/Cedar, compile to kernel policy | plugin-policy |
| Identity verifier | `actor_for(credential)->str\|None` | OAuth/OIDC/SPIFFE → actor | plugin-identity |
| Tool adapter | `mcp_call_to_action(...)->action` | framework tool call → kernel action | plugin-mcp |

## Building a plugin (the whole process)

1. New package that `depends on decision-os-min`.
2. Implement one seam above (a function/class matching the shape).
3. State its **maturity** honestly in the README (REFERENCE / INTERFACE-ONLY /
   EXPERIMENTAL) and add a **test/PoC** for every claim (Principle 8).
4. Keep it **removable** — nothing in the core should depend on your plugin
   (Principle 9).

That's it. No inheritance, no lifecycle hooks to register. A plugin is a package
that fits a seam.

## Stability

The **advisor** seam is stable across `0.x`. The adapter shapes are stable-by-
convention (documented here). Breaking a seam is a MAJOR version bump. New seams
are added only when a real plugin needs one — not speculatively.
