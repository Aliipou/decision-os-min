# Decision OS gateway

One command puts the Decision OS kernel in front of every tool your AI agents can call, in every app and with every model, and keeps a tamper-evident record of what ran.

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/Aliipou/decision-os-min/main/install.sh | sh

# Windows (PowerShell), or double-click Install-DecisionOS.cmd
irm https://raw.githubusercontent.com/Aliipou/decision-os-min/main/install.ps1 | iex
```

Then restart your AI apps. To undo everything: `decision-os uninstall`.

Want to see what it would do before it blocks anything? Install in observe mode (`sh install.sh --observe`, or `decision-os install --observe`). Every call runs and is recorded with what the policy would have decided. Switch to enforcing from the dashboard when the record looks right.

## What it covers

| Surface | How it is intercepted | What gets governed |
|---|---|---|
| MCP servers (stdio) | `decision-os install` rewrites each app's MCP config so every server starts behind `decision-os mcp-proxy` | every `tools/call` from Claude Desktop, Claude Code, Cursor, VS Code, GitHub Copilot CLI, Windsurf, Gemini CLI, OpenAI Codex, LM Studio, Kiro, Amazon Q, Cline, Roo Code |
| Model APIs | `decision-os run -- <agent>` starts a local gateway and points the agent's `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` at it | every tool call a model emits through OpenAI-compatible Chat Completions or Responses, or Anthropic Messages, streamed or not. This includes an agent's built-in tools (for example Claude Code's Bash, Edit and Write) that never touch MCP |

The model gateway works with any OpenAI-compatible endpoint: OpenAI, Ollama, LM Studio, vLLM, OpenRouter, Groq, DeepSeek, Mistral, Together, xAI, and Gemini's OpenAI-compatible API. Add others under `[llm.upstreams]`.

## How one call is decided

```text
tool call ──> Action {actor, tool, purpose, labels, arguments, nonce}
                 │
                 ├─ policy.toml  (trusted PDP: allow / ask / deny)          ─┐
                 ├─ guardrails   (veto-only: secrets, credentials, rm -rf /) ─┤ deny wins
                 ▼                                                           ─┘
              Kernel: binds the decision to this exact action, signs it, mints a one-time token
                 │
                 ▼
              Executor: checks signature, binding and token, writes the audit entry,
                        then runs the effect (forwards the call / releases it to the agent)
```

The gateway adds no new authority. Policy and guardrails produce verdicts; only the kernel signs; only the executor runs anything. Every outcome, allowed or refused, is one entry in a hash-chained log (`decision-os audit --verify`).

An `ask` verdict pauses the call and asks you. The approval is bound to the action fingerprint the kernel signs, so it unlocks that one call: same tool, same arguments, same request. A retry with one byte changed asks again. Unanswered approvals are refused after `ask_timeout_seconds`.

## Approving

When a call needs you, a desktop notification appears and the dashboard opens (`decision-os ui`, or `decision-os approve` in a terminal). You can allow once, deny, or, when the policy (not a guardrail) asked, choose "always allow" or "always deny" for that tool. Remembered choices are listed on the dashboard and can be forgotten there. An explicit `deny` rule in `policy.toml` always beats a remembered "always allow".

MCP clients have their own request timeouts. If an app gives up on a tool call before you answer, raise its timeout or lower `ask_timeout_seconds`.

## Policy

`~/.decision-os/policy.toml` (or `$DECISION_OS_HOME/policy.toml`). Changes apply on the next call. `decision-os policy check` validates it; an invalid policy refuses every call until fixed (fail closed), and the dashboard shows the error.

```toml
mode = "enforce"      # or "observe"
profile = "balanced"  # balanced | strict | open

[[rule]]              # first match wins; globs, * matches anything including /
server = "filesystem"
tool = "write_file"
args = { path = "~/projects/*" }
decision = "allow"

[[rule]]
server = "github"
tool = "*"
args = { repo = ["me/*", "my-org/public-*"] }
decision = "allow"

[[rule]]
tool = "*delete*"
decision = "deny"
reason = "nothing gets deleted by an agent"

[[rule]]
client = "claude-code"   # the app (MCP) or the agent name (model gateway)
server = "llm"           # tool calls seen by the model gateway use server "llm"
tool = "Bash"
decision = "ask"

[[rule]]
tool = "send_email"
decision = "allow"
redact = ["attachments"]  # the tool receives "[REDACTED]" for this argument
```

Profiles decide what no rule matches. `balanced` runs read-only tools (by name, and by MCP `readOnlyHint` for names it cannot classify) and asks for everything else. `strict` asks for everything. `open` runs everything. In every profile the guardrails and the audit log stay on.

`decision-os policy explain --server github --tool create_issue --args '{"repo":"me/x"}'` prints what would happen and why, without running anything.

### Guardrails

Deterministic checks that run on every call as a veto. Each can be `deny`, `ask` or `off`:

| Check | Default | Examples |
|---|---|---|
| `protected_paths` | deny | `~/.ssh`, `~/.aws`, `~/.gnupg`, cloud CLIs, `~/.netrc`, `~/.npmrc`, keychains |
| `secret_files` | ask | `.env`, `*.pem`, `*.key`, `id_rsa*`, `credentials.json` |
| `secrets_in_arguments` | deny | private keys, AWS, GitHub, OpenAI, Anthropic, Slack, Google, Stripe, Hugging Face tokens |
| `catastrophic_commands` | deny | `rm -rf /` or `~`, `mkfs`, `dd` onto a disk, fork bombs, `format C:` |
| `risky_commands` | ask | `git push --force`, `git reset --hard`, `DROP TABLE`, `curl ... \| sh`, `sudo`, `terraform destroy`, `npm publish` |

Self-protection is always on and cannot be observed away: no governed call may touch `~/.decision-os` or any MCP client config. That is how an agent would otherwise approve its own request or unwrap the gateway. Secrets are never copied into the audit log or the approval screen.

The checks are pattern-based, not a shell parser. They err toward asking (`echo "rm -rf is scary"` asks), and a determined agent can phrase a command they do not recognize. They are a safety net under the policy, not a sandbox.

## The model gateway

```bash
decision-os run -- claude                 # Claude Code, built-in tools included
decision-os run -- aider --model gpt-5
decision-os run --upstream openai=http://localhost:11434/v1 -- my-agent.py   # Ollama
decision-os llm --port 8787               # a standing gateway for anything you point at it
```

`run` sets `OPENAI_BASE_URL`, `OPENAI_API_BASE` and `ANTHROPIC_BASE_URL` for the agent. The official OpenAI and Anthropic SDKs read these variables. If the agent already had a custom base URL, that becomes the upstream. Each tool call in a model response becomes a governed action. A refused call is removed from the response and replaced with a short assistant note, so the agent loop continues and the model learns why on its next turn. `LIMIT` redactions rewrite the call's arguments. Streams are relayed live until the first tool call, then held to the end of that message so a call is never half-delivered. When nothing is refused, the stream is byte-for-byte what the model sent.

## Commands

| Command | |
|---|---|
| `decision-os install [--observe] [--profile P] [--client ID] [--project DIR] [--dry-run]` | govern every stdio MCP server; prints what changed |
| `decision-os uninstall` | restore configs (byte-for-byte when the app has not edited them since) |
| `decision-os status` | what is governed, per app |
| `decision-os ui` | dashboard: approvals, activity, coverage, remembered choices, observe switch |
| `decision-os approve` | answer approvals in the terminal |
| `decision-os audit [--verify] [--summary] [--json]` | the hash-chained record |
| `decision-os policy check \| show \| path \| explain` | |
| `decision-os observe on \| off` | |
| `decision-os run -- <agent>` / `decision-os llm` | model gateway |
| `decision-os doctor` | checks Python, policy, key, audit chain, and that every wrapped server's command still resolves |

Every write to an app's config is atomic, verified by re-parsing, and backed up first under `~/.decision-os/backups/`. JSON files with comments (some VS Code setups) are left alone unless you pass `--force-jsonc`, because a rewrite would drop the comments. Codex's TOML is edited line by line, so its comments survive. Remote (HTTP/SSE) MCP servers are reported and left as they are: the app runs their sign-in flow itself.

## Trust model and limits

Stated plainly, so nobody reads more into it than is there:

* **Same-user boundary.** The gateway stops governed tool calls from touching its own state, but any program running as your OS user can edit `~/.decision-os` directly, including approving its own request. For a hard boundary, run agents as a separate user or inside the Docker profile in [`sandbox/`](../sandbox/).
* **Coverage is what is routed through it.** MCP servers an app adds after `install` are not governed until you run `install` again (`decision-os status` shows them). Remote MCP servers are not proxied. An agent that ignores its base-URL setting, or talks to a model another way (for example Codex signed in with a ChatGPT account), is not covered by the model gateway.
* **Client identity is a label, not authentication.** `--client` and the `X-Decision-OS-Agent` header say which app is calling; they are not verified.
* **Annotations are hints from the server.** A server could mark a harmful tool `readOnlyHint`. They can make an unclassifiable name run under `balanced`, never override a write verb, a rule or a guardrail. Use `strict` or explicit rules for servers you do not trust.
* **Paths are normalized, not resolved.** `..` is collapsed before matching; symlinks are not followed, and relative paths are matched as written.
* **The model gateway governs delivery, not execution.** It decides whether the agent receives a tool call. Execution then happens inside the agent.

## Files

Everything lives in `~/.decision-os` (`DECISION_OS_HOME` overrides): `policy.toml`, `learned.json` (remembered choices), `audit.jsonl`, `kernel.pem` (Ed25519 signing key, mode 0600), `spent.sqlite` (one-time tokens), `approvals/`, `backups/`, `state.json` (what `install` changed).
