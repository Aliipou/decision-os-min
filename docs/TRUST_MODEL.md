# Trust model

> Reference core: [`decision_os_min/`](../decision_os_min). See also
> [WHY.md](WHY.md) · [ARCHITECTURE.md](ARCHITECTURE.md) ·
> [THREAT_MODEL.md](THREAT_MODEL.md) · [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md) ·
> [README](../README.md)

Everything in `decision-os-min` reduces to one question: **who is trusted, and
why?** The answer is deliberately narrow.

## Authority = possession of the signing key

Authority in this system is *not* a role, a flag, or a claim in a request. It is
**possession of the Ed25519 private key**, and that key is held only by the
kernel:

```python
# decision_os_min/kernel.py
class Kernel:
    def __init__(self, policy, _key=None):
        self._key = _key or Ed25519PrivateKey.generate()   # the sole authority
        self._pub = self._key.public_key().public_bytes_raw().hex()
    ...
    def _sign(self, obj):
        return self._key.sign(_canonical(obj)).hex()
```

Only [`Kernel._sign`](../decision_os_min/kernel.py) uses the private key, and it
is the only place decisions and tokens are signed. Everyone else holds at most
the *public* key ([`Executor.__init__`](../decision_os_min/execute.py) receives
`kernel_public_key`), which lets them **verify** authority but never **exercise**
it. [`verify`](../decision_os_min/kernel.py) accepts an object only if it both
carries `issued_by == KERNEL_IDENTITY` *and* validates against that public key —
so identity without a signature, or a signature without the matching key, is
worthless.

## What is trusted

- **The kernel process** — because it holds the key and the policy, and because
  it alone produces signed decisions and tokens. If the kernel is honest, the
  system's guarantees hold. If it is compromised, they do not (see
  [THREAT_MODEL.md](THREAT_MODEL.md), residual risks).
- **The Ed25519 signature verification** and the SHA-256 hash chain — the
  cryptographic primitives from the `cryptography` library and stdlib `hashlib`.

That is the whole trusted base.

## What is UNtrusted

Everything else is treated as adversary-controllable input and is checked, never
believed:

- **The caller / the agent.** It supplies the `Action` dict — any `actor`,
  `capability`, `purpose`, `labels`, `payload`. The kernel evaluates these
  against policy; nothing in the request grants authority by itself. The caller
  cannot mint a token or sign a decision.
- **The transport.** Assumed to be a possible MITM that can mutate the
  `result` dict in flight. Mutation is defeated by signature verification and
  action-binding in [`Executor.execute`](../decision_os_min/execute.py), not by
  trusting the channel.
- **The tools.** Tool functions are passed *into* the executor
  (`tools: dict[str, Callable]`) and are invoked only after all gates pass, only
  for the authority-bound tool name, and — for LIMIT — only against the redacted
  `transformed_payload`. The tools are effect-executors, not policy-makers.
- **The advisor.** An advisor is an optional plugin returning a `threat_class`.
  It is *advice, not authority*: the kernel decides, an advisor can only
  *tighten* a verdict, and it can never loosen a DENY or produce a signature.
  See [`advisors.py`](../decision_os_min/advisors.py) and
  `test_advisor_plugin_can_only_tighten`.

## The single-authority rule

There is exactly **one** signer. No component other than the kernel holds the
private key, and no verdict is honored unless it is signed by that key. This is
what makes "mandatory mediation" real: an effect cannot happen through any path
that skips the one authority, because the executor demands a valid kernel
signature before it will run anything.

## The single audit truth

There is exactly **one** audit mechanism: the append-only, hash-chained
[`HashLog`](../decision_os_min/audit.py). By design there is *no* second source
— no separate notary, no dual log to reconcile. One log means there is one
answer to "what was authorized," and its integrity is self-verifiable via
`verify()`. A dual-source design would create the possibility of two truths
disagreeing; this core refuses that.

## Summary

| Party | Trusted? | Why |
|---|---|---|
| Kernel process | **Yes** | Holds the signing key + policy; sole producer of signed decisions/tokens |
| Signature / hash primitives | **Yes** | Ed25519 + SHA-256 are the root of verification |
| Caller / agent | No | Supplies untrusted input; checked against policy, holds no key |
| Transport | No | Assumed MITM; defeated by signatures + action-binding |
| Tools | No | Invoked only post-gates, for the bound tool, on the authorized payload |
| Advisor | No | Advice only; can tighten, never loosen; holds no authority |
| Audit file on disk | No | Insider-writable; tampering is *detected*, not prevented |
