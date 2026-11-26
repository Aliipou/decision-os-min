"""A model-agnostic gateway: gate the tool calls a model emits, before the agent
receives them.

    agent  --HTTP-->  decision-os llm gateway  --HTTP-->  model API
                         (OpenAI chat / Responses, Anthropic Messages)

This covers what MCP wrapping cannot: an agent's *built-in* tools (Claude Code's
Bash/Edit/Write, Codex's shell, Aider's edits) and any framework that calls a
model directly. It works with any OpenAI-compatible endpoint (OpenAI, Ollama,
LM Studio, vLLM, OpenRouter, Groq, DeepSeek, Mistral, Together, xAI, Gemini's
OpenAI-compatible API) and with Anthropic's Messages API.

For each tool call in a model response the gateway builds a governed action
(server ``llm``). The *effect* is releasing that tool call to the agent, so it
runs inside ``Executor.execute`` like any other effect. A refused call is removed
from the response and replaced by a short assistant note, so the agent loop
continues and the model learns why on its next turn. ``LIMIT`` redactions rewrite
the call's arguments. Streams are relayed live until the first tool call, then
buffered to the end of the message so a call is never half-delivered.

Honest scope: this governs what reaches the agent. An agent that ignores its
base-URL setting, or talks to a model through another route, is not covered.
"""

from __future__ import annotations

import io
import json
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .engine import Gateway
from .paths import Home
from .policy import DEFAULT_UPSTREAMS, PolicyError, load_policy

AGENT_HEADER = "x-decision-os-agent"
HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
    AGENT_HEADER,
}
# Responses API items the *agent* executes. Anything else ending in "_call" that
# is not known to run on the provider's side is gated too (fail closed).
SERVER_EXECUTED_ITEMS = {
    "web_search_call",
    "file_search_call",
    "code_interpreter_call",
    "image_generation_call",
    "mcp_call",
    "tool_search_call",
}


class _GatedItems:
    def __contains__(self, kind: object) -> bool:
        return (
            isinstance(kind, str) and kind.endswith("_call") and kind not in SERVER_EXECUTED_ITEMS
        )


GATED_RESPONSE_ITEMS = _GatedItems()
_ITEM_META = {"type", "id", "call_id", "status", "name"}


# ------------------------------------------------------------------ deciding


class ToolCallJudge:
    """Turns one model tool call into a governed action."""

    def __init__(self, gateway: Gateway, model: str | None) -> None:
        self.gw = gateway
        self.model = model

    def judge(self, name: str, raw_args: Any) -> tuple[bool, Any, str | None]:
        """Return (keep, new_raw_args_or_None, note_if_blocked)."""
        was_string = isinstance(raw_args, str)
        if was_string:
            try:
                args = json.loads(raw_args) if raw_args.strip() else {}
            except ValueError:
                args = {"_raw": raw_args}
        else:
            args = raw_args if raw_args is not None else {}
        if not isinstance(args, dict):
            args = {"_value": args}
        res = self.gw.govern(
            server="llm",
            tool=name,
            arguments=args,
            model=self.model,
            release=lambda payload: payload,
        )
        if not res.executed:
            return False, None, f"[Decision OS] Blocked the `{name}` tool call: {res.reason}"
        out = res.output
        if out == args:
            return True, None, None
        if set(out) == {"_raw"}:
            new: Any = out["_raw"]
        elif set(out) == {"_value"}:
            new = out["_value"]
        else:
            new = out
        if was_string and not isinstance(new, str):
            new = json.dumps(new, ensure_ascii=False)
        return True, new, None


def _join_notes(existing: str | None, notes: list[str]) -> str:
    text = "\n".join(notes)
    return f"{existing}\n\n{text}" if existing else text


# ---------------------------------------------------------- non-stream bodies


def _chat_call(tc: Any) -> tuple[str | None, Any, str]:
    """(name, raw arguments, kind) of a chat tool call: function or custom."""
    if not isinstance(tc, dict):
        return None, None, ""
    fn, custom = tc.get("function"), tc.get("custom")
    if isinstance(fn, dict) and fn.get("name"):
        return str(fn["name"]), fn.get("arguments"), "function"
    if isinstance(custom, dict) and custom.get("name"):
        return str(custom["name"]), {"input": custom.get("input", "")}, "custom"
    return None, None, ""


def _chat_call_with(tc: dict[str, Any], kind: str, new: Any) -> dict[str, Any]:
    if kind == "custom":
        value = new.get("input", "") if isinstance(new, dict) else str(new)
        return {**tc, "custom": {**tc["custom"], "input": value}}
    return {**tc, "function": {**tc["function"], "arguments": new}}


def gate_chat_completion(body: dict[str, Any], judge: ToolCallJudge) -> dict[str, Any]:
    for choice in body.get("choices") or []:
        msg = choice.get("message")
        if not isinstance(msg, dict):
            continue
        notes: list[str] = []
        changed = False
        tcs = msg.get("tool_calls")
        if isinstance(tcs, list) and tcs:
            kept = []
            for tc in tcs:
                name, args, kind = _chat_call(tc)
                if name is None:  # a tool call we cannot read is not delivered
                    notes.append("[Decision OS] Blocked a tool call in an unrecognized format.")
                    continue
                ok, new_args, note = judge.judge(name, args)
                if ok:
                    if new_args is not None:
                        tc = _chat_call_with(tc, kind, new_args)
                        changed = True
                    kept.append(tc)
                else:
                    notes.append(note or "")
            if notes or changed:
                if kept:
                    msg["tool_calls"] = kept
                else:
                    msg.pop("tool_calls", None)
                    if choice.get("finish_reason") == "tool_calls":
                        choice["finish_reason"] = "stop"
        fc = msg.get("function_call")
        if isinstance(fc, dict) and fc.get("name"):
            ok, new_args, note = judge.judge(fc["name"], fc.get("arguments"))
            if not ok:
                msg.pop("function_call", None)
                notes.append(note or "")
                if choice.get("finish_reason") == "function_call":
                    choice["finish_reason"] = "stop"
            elif new_args is not None:
                msg["function_call"] = {**fc, "arguments": new_args}
        if notes:
            msg["content"] = _join_notes(msg.get("content"), notes)
    return body


def gate_anthropic_message(body: dict[str, Any], judge: ToolCallJudge) -> dict[str, Any]:
    content = body.get("content")
    if not isinstance(content, list):
        return body
    kept, notes = [], []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name"):
            ok, new_input, note = judge.judge(block["name"], block.get("input"))
            if ok:
                kept.append({**block, "input": new_input} if new_input is not None else block)
            else:
                notes.append(note or "")
        else:
            kept.append(block)
    if notes:
        kept.append({"type": "text", "text": "\n".join(notes)})
        if (
            not any(isinstance(b, dict) and b.get("type") == "tool_use" for b in kept)
            and body.get("stop_reason") == "tool_use"
        ):
            body["stop_reason"] = "end_turn"
    body["content"] = kept
    return body


def _response_item_args(item: dict[str, Any]) -> tuple[str, Any]:
    t = str(item.get("type"))
    if t == "function_call":
        return item.get("name") or "function", item.get("arguments")
    if t == "custom_tool_call":
        return item.get("name") or "custom_tool", {"input": item.get("input", "")}
    # local_shell_call, shell_call, apply_patch_call, computer_call, future kinds:
    # the tool is named after the item type, its arguments are the item's fields.
    name = item.get("name") or t.removesuffix("_call")
    return name, {k: v for k, v in item.items() if k not in _ITEM_META}


def _apply_response_item(item: dict[str, Any], new: Any) -> dict[str, Any]:
    t = item.get("type")
    if t == "function_call":
        return {**item, "arguments": new}
    if t == "custom_tool_call":
        return {**item, "input": new.get("input", "") if isinstance(new, dict) else str(new)}
    if isinstance(new, dict):
        return {**{k: v for k, v in item.items() if k in _ITEM_META}, **new}
    return item


def _note_item(notes: list[str]) -> dict[str, Any]:
    return {
        "type": "message",
        "id": f"msg_dos_{uuid.uuid4().hex[:20]}",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "text": "\n".join(notes), "annotations": []}],
    }


def gate_response_output(output: list[Any], judge: ToolCallJudge) -> tuple[list[Any], bool]:
    kept, notes, changed = [], [], False
    for item in output:
        if isinstance(item, dict) and item.get("type") in GATED_RESPONSE_ITEMS:
            name, args = _response_item_args(item)
            ok, new, note = judge.judge(name, args)
            if ok:
                if new is not None:
                    item = _apply_response_item(item, new)
                    changed = True
                kept.append(item)
            else:
                notes.append(note or "")
                changed = True
        else:
            kept.append(item)
    if notes:
        kept.append(_note_item(notes))
    return kept, changed


def gate_responses_body(body: dict[str, Any], judge: ToolCallJudge) -> dict[str, Any]:
    if isinstance(body.get("output"), list):
        body["output"], _ = gate_response_output(body["output"], judge)
    return body


# --------------------------------------------------------------- SSE helpers


def sse_events(stream: Any) -> Iterator[tuple[bytes, str | None, str | None]]:
    """Yield (raw_event_bytes, event_name, data) per SSE event."""
    lines: list[bytes] = []
    while True:
        line = stream.readline()
        if not line:
            if lines:
                yield _parse_sse(lines)
            return
        lines.append(line)
        if line in (b"\n", b"\r\n"):
            yield _parse_sse(lines)
            lines = []


def _parse_sse(lines: list[bytes]) -> tuple[bytes, str | None, str | None]:
    raw = b"".join(lines)
    event = None
    data_parts: list[str] = []
    for line in lines:
        text = line.decode("utf-8", "replace").rstrip("\r\n")
        if text.startswith("event:"):
            event = text[6:].strip()
        elif text.startswith("data:"):
            data_parts.append(text[5:][1:] if text[5:].startswith(" ") else text[5:])
    if not raw.endswith((b"\n\n", b"\r\n\r\n")):
        raw = raw.rstrip(b"\r\n") + b"\n\n"
    return raw, event, ("\n".join(data_parts) if data_parts else None)


def sse(data: dict[str, Any] | str, event: str | None = None) -> bytes:
    payload = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {payload}\n\n".encode()


Write = Callable[[bytes], None]


# ------------------------------------------------------------ stream: chat


def stream_chat(stream: Any, write: Write, judge: ToolCallJudge) -> None:
    buffering = False
    buffered: list[tuple[bytes, dict[str, Any] | None]] = []
    calls: dict[tuple[int, int], dict[str, Any]] = {}
    order: list[tuple[int, int]] = []
    finish: dict[int, str | None] = {}
    late_text: dict[int, list[str]] = {}
    role_sent: set[int] = set()
    template: dict[str, Any] | None = None
    done_raw = b"data: [DONE]\n\n"
    for raw, _event, data in sse_events(stream):
        if data is None:
            if buffering:
                buffered.append((raw, None))
            else:
                write(raw)
            continue
        if data.strip() == "[DONE]":
            done_raw = raw
            break
        try:
            chunk = json.loads(data)
        except ValueError:
            if buffering:
                buffered.append((raw, None))
            else:
                write(raw)
            continue
        choices = chunk.get("choices") or []
        if any(
            isinstance(c.get("delta"), dict)
            and (c["delta"].get("tool_calls") or c["delta"].get("function_call"))
            for c in choices
            if isinstance(c, dict)
        ):
            buffering = True
        if template is None and choices:
            template = chunk
        if not buffering:
            for c in choices:
                if (
                    isinstance(c, dict)
                    and isinstance(c.get("delta"), dict)
                    and c["delta"].get("role")
                ):
                    role_sent.add(c.get("index", 0))
            write(raw)
            continue
        buffered.append((raw, chunk))
        for c in choices:
            if not isinstance(c, dict):
                continue
            ci = c.get("index", 0)
            delta = c.get("delta") or {}
            if c.get("finish_reason"):
                finish[ci] = c["finish_reason"]
            if delta.get("content"):
                late_text.setdefault(ci, []).append(delta["content"])
            for tc in delta.get("tool_calls") or []:
                key = (ci, tc.get("index", 0))
                if key not in calls:
                    calls[key] = {"id": None, "name": "", "args": [], "type": "function"}
                    order.append(key)
                st = calls[key]
                st["id"] = tc.get("id") or st["id"]
                st["type"] = tc.get("type") or st["type"]
                part = (
                    tc.get("custom") if isinstance(tc.get("custom"), dict) else tc.get("function")
                )
                part = part if isinstance(part, dict) else {}
                if isinstance(tc.get("custom"), dict):
                    st["type"] = "custom"
                if part.get("name"):
                    st["name"] += part["name"]
                piece = part.get("input") if st["type"] == "custom" else part.get("arguments")
                if piece:
                    st["args"].append(piece)
            fc = delta.get("function_call")
            if fc:
                key = (ci, -1)
                if key not in calls:
                    calls[key] = {"id": None, "name": "", "args": [], "type": "legacy"}
                    order.append(key)
                if fc.get("name"):
                    calls[key]["name"] += fc["name"]
                if fc.get("arguments"):
                    calls[key]["args"].append(fc["arguments"])
    if not buffering:
        write(done_raw)
        return
    verdicts: dict[tuple[int, int], tuple[bool, Any, str | None]] = {}
    for key in order:
        st = calls[key]
        if not st["name"]:
            verdicts[key] = (False, None, "[Decision OS] Blocked a tool call with no name.")
        elif st["type"] == "custom":
            verdicts[key] = judge.judge(st["name"], {"input": "".join(st["args"])})
        else:
            verdicts[key] = judge.judge(st["name"], "".join(st["args"]))
    if all(ok and new is None for ok, new, _ in verdicts.values()):
        for raw, _ in buffered:
            write(raw)
        write(done_raw)
        return
    tpl = template or (buffered[0][1] if buffered and buffered[0][1] else {})
    keys = ("id", "object", "created", "model", "system_fingerprint")
    base: dict[str, Any] = {k: tpl[k] for k in keys if k in tpl}
    base.setdefault("object", "chat.completion.chunk")

    def make_chunk(ci: int, delta: dict[str, Any], fin: str | None = None) -> bytes:
        return sse({**base, "choices": [{"index": ci, "delta": delta, "finish_reason": fin}]})

    for ci in sorted({k[0] for k in order} | set(late_text) | set(finish)):
        delta_role = {} if ci in role_sent else {"role": "assistant"}
        if late_text.get(ci):
            write(make_chunk(ci, {**delta_role, "content": "".join(late_text[ci])}))
            delta_role = {}
        kept_n = 0
        notes = []
        for key in [k for k in order if k[0] == ci]:
            ok, new, note = verdicts[key]
            st = calls[key]
            args = "".join(st["args"]) if new is None else new
            if st["type"] == "custom" and isinstance(args, dict):
                args = args.get("input", "")
            if not ok:
                notes.append(note or "")
                continue
            if st["type"] == "custom":
                write(
                    make_chunk(
                        ci,
                        {
                            **delta_role,
                            "tool_calls": [
                                {
                                    "index": kept_n,
                                    "id": st["id"],
                                    "type": "custom",
                                    "custom": {"name": st["name"], "input": args},
                                }
                            ],
                        },
                    )
                )
                delta_role = {}
                kept_n += 1
                continue
            if st["type"] == "legacy":
                write(
                    make_chunk(
                        ci, {**delta_role, "function_call": {"name": st["name"], "arguments": args}}
                    )
                )
            else:
                write(
                    make_chunk(
                        ci,
                        {
                            **delta_role,
                            "tool_calls": [
                                {
                                    "index": kept_n,
                                    "id": st["id"],
                                    "type": "function",
                                    "function": {"name": st["name"], "arguments": args},
                                }
                            ],
                        },
                    )
                )
            delta_role = {}
            kept_n += 1
        if notes:
            write(
                make_chunk(
                    ci,
                    {
                        **delta_role,
                        "content": ("\n\n" if ci in role_sent else "") + "\n".join(notes),
                    },
                )
            )
        fin = finish.get(ci)
        if kept_n == 0 and fin in ("tool_calls", "function_call"):
            fin = "stop"
        write(make_chunk(ci, {}, fin or ("tool_calls" if kept_n else "stop")))
    for raw, parsed in buffered:  # trailing usage chunks (no choices)
        if parsed is not None and not parsed.get("choices"):
            write(raw)
    write(done_raw)


# ------------------------------------------------------- stream: anthropic


def stream_anthropic(stream: Any, write: Write, judge: ToolCallJudge) -> None:
    buffering = False
    buffered: list[tuple[bytes, dict[str, Any] | None]] = []
    first_idx = 0
    for raw, _event, data in sse_events(stream):
        parsed = None
        if data is not None:
            try:
                parsed = json.loads(data)
            except ValueError:
                parsed = None
        t = parsed.get("type") if isinstance(parsed, dict) else None
        block = parsed.get("content_block") if isinstance(parsed, dict) else None
        if (
            not buffering
            and t == "content_block_start"
            and isinstance(block, dict)
            and block.get("type") == "tool_use"
        ):
            buffering = True
            first_idx = parsed.get("index", 0) if isinstance(parsed, dict) else 0
        if not buffering:
            write(raw)
            continue
        buffered.append((raw, parsed))
        if t == "message_stop":
            break
    if not buffering:
        return
    blocks: dict[int, dict[str, Any]] = {}
    for _, p in buffered:
        if not isinstance(p, dict):
            continue
        if p.get("type") == "content_block_start":
            blocks[p.get("index", 0)] = {"block": p.get("content_block") or {}, "json": []}
        elif p.get("type") == "content_block_delta":
            d = p.get("delta") or {}
            if d.get("type") == "input_json_delta" and p.get("index", 0) in blocks:
                blocks[p.get("index", 0)]["json"].append(d.get("partial_json", ""))
    verdicts: dict[int, tuple[bool, Any, str | None]] = {}
    for idx, b in blocks.items():
        blk = b["block"]
        if blk.get("type") != "tool_use":
            continue
        joined = "".join(b["json"])
        try:
            args = json.loads(joined) if joined.strip() else (blk.get("input") or {})
        except ValueError:
            args = {"_raw": joined}
        verdicts[idx] = judge.judge(blk.get("name", "tool"), args)
    if all(ok and new is None for ok, new, _ in verdicts.values()):
        for raw, _ in buffered:
            write(raw)
        return
    notes = [n or "" for ok, _, n in verdicts.values() if not ok]
    any_tool_kept = any(ok for ok, _, _ in verdicts.values())
    remap: dict[int, int] = {}
    nxt = first_idx
    note_written = False

    def emit_note() -> None:
        nonlocal note_written, nxt
        if notes and not note_written:
            write(
                sse(
                    {
                        "type": "content_block_start",
                        "index": nxt,
                        "content_block": {"type": "text", "text": ""},
                    },
                    "content_block_start",
                )
            )
            write(
                sse(
                    {
                        "type": "content_block_delta",
                        "index": nxt,
                        "delta": {"type": "text_delta", "text": "\n".join(notes)},
                    },
                    "content_block_delta",
                )
            )
            write(sse({"type": "content_block_stop", "index": nxt}, "content_block_stop"))
            nxt += 1
            note_written = True

    for raw, p in buffered:
        if not isinstance(p, dict):
            write(raw)
            continue
        t = p.get("type")
        idx = p.get("index", 0)
        if t == "content_block_start":
            v = verdicts.get(idx)
            if v is not None and not v[0]:
                continue
            remap[idx] = nxt
            nxt += 1
            if v is not None and v[1] is not None:
                blk = {**(p.get("content_block") or {}), "input": {}}
                write(sse({**p, "index": remap[idx], "content_block": blk}, t))
                write(
                    sse(
                        {
                            "type": "content_block_delta",
                            "index": remap[idx],
                            "delta": {
                                "type": "input_json_delta",
                                "partial_json": json.dumps(v[1], ensure_ascii=False),
                            },
                        },
                        "content_block_delta",
                    )
                )
            else:
                write(sse({**p, "index": remap[idx]}, t))
        elif t in ("content_block_delta", "content_block_stop"):
            if idx not in remap:
                continue
            v = verdicts.get(idx)
            if t == "content_block_delta" and v is not None and v[1] is not None:
                continue
            write(sse({**p, "index": remap[idx]}, t))
        elif t == "message_delta":
            emit_note()
            delta = dict(p.get("delta") or {})
            if not any_tool_kept and delta.get("stop_reason") == "tool_use":
                delta["stop_reason"] = "end_turn"
            write(sse({**p, "delta": delta}, t))
        else:
            if t == "message_stop":
                emit_note()
            write(sse(p, t) if t else raw)
    emit_note()


# -------------------------------------------------------- stream: responses


def stream_responses(stream: Any, write: Write, judge: ToolCallJudge) -> None:
    buffering = False
    buffered: list[tuple[bytes, str | None, dict[str, Any] | None]] = []
    for raw, event, data in sse_events(stream):
        parsed = None
        if data is not None and data.strip() != "[DONE]":
            try:
                parsed = json.loads(data)
            except ValueError:
                parsed = None
        t = parsed.get("type") if isinstance(parsed, dict) else event
        added = parsed.get("item") if isinstance(parsed, dict) else None
        if (
            not buffering
            and t == "response.output_item.added"
            and isinstance(added, dict)
            and added.get("type") in GATED_RESPONSE_ITEMS
        ):
            buffering = True
        if not buffering:
            write(raw)
            continue
        buffered.append((raw, t, parsed))
        if t in ("response.completed", "response.incomplete", "response.failed"):
            break
    if not buffering:
        return
    final_items: dict[int, dict[str, Any]] = {}
    for _, t, p in buffered:
        if t == "response.output_item.done" and isinstance(p, dict):
            final_items[p.get("output_index", 0)] = p.get("item") or {}
    verdicts: dict[int, tuple[bool, Any, str | None]] = {}
    for oi, item in final_items.items():
        if item.get("type") in GATED_RESPONSE_ITEMS:
            name, args = _response_item_args(item)
            verdicts[oi] = judge.judge(name, args)
    if all(ok and new is None for ok, new, _ in verdicts.values()):
        for raw, _, _ in buffered:
            write(raw)
        return
    notes = [n or "" for ok, _, n in verdicts.values() if not ok]
    seq = next(
        (
            p.get("sequence_number")
            for _, _, p in buffered
            if isinstance(p, dict) and isinstance(p.get("sequence_number"), int)
        ),
        None,
    )
    remap: dict[int, int] = {}
    nxt = min(verdicts) if verdicts else 0
    note_item = _note_item(notes) if notes else None

    def out(p: dict[str, Any], t: str) -> None:
        nonlocal seq
        if seq is not None:
            p = {**p, "sequence_number": seq}
            seq += 1
        write(sse(p, t))

    def index_of(oi: int) -> int:
        if oi not in remap:
            nonlocal nxt
            remap[oi] = nxt
            nxt += 1
        return remap[oi]

    for raw, t, p in buffered:
        if not isinstance(p, dict) or t is None:
            write(raw)
            continue
        if t in ("response.completed", "response.incomplete", "response.failed"):
            if note_item is not None:
                ni = nxt
                out(
                    {
                        "type": "response.output_item.added",
                        "output_index": ni,
                        "item": {**note_item, "status": "in_progress"},
                    },
                    "response.output_item.added",
                )
                out(
                    {"type": "response.output_item.done", "output_index": ni, "item": note_item},
                    "response.output_item.done",
                )
            resp = dict(p.get("response") or {})
            if isinstance(resp.get("output"), list):
                kept = []
                for i, item in enumerate(resp["output"]):
                    v = verdicts.get(i)
                    if v is not None and not v[0]:
                        continue
                    if v is not None and v[1] is not None:
                        item = _apply_response_item(item, v[1])
                    kept.append(item)
                if note_item is not None:
                    kept.append(note_item)
                resp["output"] = kept
            out({**p, "response": resp}, t)
            continue
        out_idx = p.get("output_index")
        if not isinstance(out_idx, int):
            out(p, t)
            continue
        v = verdicts.get(out_idx)
        if v is not None and not v[0]:
            continue  # blocked item: drop all of its events
        if out_idx < (min(verdicts) if verdicts else 0):
            out(p, t)
            continue
        new_oi = index_of(out_idx)
        if v is not None and v[1] is not None:  # transformed: only full added/done items
            if t == "response.output_item.done":
                item = _apply_response_item(p.get("item") or {}, v[1])
                out(
                    {
                        "type": "response.output_item.added",
                        "output_index": new_oi,
                        "item": {**item, "status": "in_progress"},
                    },
                    "response.output_item.added",
                )
                out({**p, "output_index": new_oi, "item": item}, t)
            continue
        out({**p, "output_index": new_oi}, t)


# ------------------------------------------------------------------ server


class _Body:
    """A decoded response body that quacks like the urllib response we read."""

    def __init__(self, data: bytes, headers: Any) -> None:
        self._buf = io.BytesIO(data)
        self.headers = headers

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def readline(self) -> bytes:
        return self._buf.readline()

    def close(self) -> None:
        pass


def detect_shape(path: str) -> str | None:
    p = path.split("?", 1)[0].rstrip("/")
    if p.endswith("/chat/completions"):
        return "chat"
    if p.endswith("/responses"):
        return "responses"
    if p.endswith("/messages"):
        return "anthropic"
    return None


class LlmGateway:
    def __init__(
        self,
        home: Home | None = None,
        *,
        agent: str = "llm-client",
        upstreams: dict[str, str] | None = None,
        interactive: bool = True,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.home = (home or Home.resolve()).ensure()
        self.default_agent = agent
        self.interactive = interactive
        self._extra = dict(upstreams or {})
        self._gateways: dict[str, Gateway] = {}
        self._lock = threading.Lock()
        self._ssl = ssl_context
        self.server: ThreadingHTTPServer | None = None

    def upstreams(self) -> dict[str, str]:
        try:
            ups = load_policy(self.home.policy).upstream_map
        except PolicyError:
            ups = dict(DEFAULT_UPSTREAMS)
        ups.update(self._extra)
        return ups

    def gateway_for(self, agent: str) -> Gateway:
        with self._lock:
            gw = self._gateways.get(agent)
            if gw is None:
                gw = Gateway(client=agent, home=self.home, interactive=self.interactive)
                self._gateways[agent] = gw
            return gw

    def serve(self, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
        gateway = self

        class Handler(_Handler):
            gw = gateway

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.server.daemon_threads = True
        return self.server

    def serve_in_thread(self, host: str = "127.0.0.1", port: int = 0) -> int:
        srv = self.serve(host, port)
        threading.Thread(target=srv.serve_forever, name="dos-llm", daemon=True).start()
        return srv.server_address[1]


class _Handler(BaseHTTPRequestHandler):
    gw: LlmGateway
    protocol_version = "HTTP/1.1"
    server_version = "DecisionOS"

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        pass

    def do_GET(self) -> None:
        self._proxy()

    def do_POST(self) -> None:
        self._proxy()

    def do_PUT(self) -> None:
        self._proxy()

    def do_DELETE(self) -> None:
        self._proxy()

    def do_PATCH(self) -> None:
        self._proxy()

    # ---- helpers
    def _reply(
        self,
        status: int,
        body: bytes,
        ctype: str = "application/json",
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.send_response(status)
        for k, v in headers or []:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _error(self, status: int, message: str) -> None:
        self._reply(
            status,
            json.dumps({"error": {"type": "decision_os_error", "message": message}}).encode(),
        )

    def _target(self) -> tuple[str, str] | None:
        path = self.path
        if path.startswith("/openai/"):
            path = "/u/openai/" + path[len("/openai/") :]
        elif path.startswith("/anthropic/"):
            path = "/u/anthropic/" + path[len("/anthropic/") :]
        if not path.startswith("/u/"):
            return None
        name, _, rest = path[3:].partition("/")
        base = self.gw.upstreams().get(name)
        if not base:
            return None
        return name, base.rstrip("/") + "/" + rest

    def _proxy(self) -> None:
        if self.path in ("/healthz", "/"):
            self._reply(200, b'{"ok":true,"service":"decision-os-llm-gateway"}')
            return
        target = self._target()
        if target is None:
            self._error(404, "unknown route; use /u/<upstream>/... (see decision-os llm upstreams)")
            return
        _, url = target
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        agent = self.headers.get(AGENT_HEADER) or self.gw.default_agent
        shape = detect_shape(url) if self.command == "POST" else None
        model = None
        if shape and body:
            try:
                req = json.loads(body)
                model = req.get("model") if isinstance(req, dict) else None
            except ValueError:
                shape = None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        headers["Accept-Encoding"] = "identity"
        request = urllib.request.Request(
            url,
            data=body if body or self.command in ("POST", "PUT", "PATCH") else None,
            headers=headers,
            method=self.command,
        )
        try:
            resp = urllib.request.urlopen(request, timeout=900, context=self.gw._ssl)
        except urllib.error.HTTPError as exc:
            resp = exc  # an HTTP error response is still a response: relay it
        except (urllib.error.URLError, OSError) as exc:
            self._error(502, f"upstream unreachable: {exc}")
            return
        try:
            self._relay(resp, shape, agent, model)
        finally:
            try:
                resp.close()
            except Exception:
                pass

    def _relay(self, resp: Any, shape: str | None, agent: str, model: str | None) -> None:
        status = getattr(resp, "status", None) or resp.getcode()
        ctype = resp.headers.get("Content-Type", "")
        passthrough_headers = [
            (k, v)
            for k, v in resp.headers.items()
            if k.lower() not in HOP and k.lower() != "content-type"
        ]
        if shape is None or status != 200:
            data = resp.read()
            self._reply(status, data, ctype or "application/octet-stream", passthrough_headers)
            return
        judge = ToolCallJudge(self.gw.gateway_for(agent), model)
        encoding = (resp.headers.get("Content-Encoding") or "identity").lower().strip()
        passthrough_headers = [
            (k, v) for k, v in passthrough_headers if k.lower() != "content-encoding"
        ]
        if encoding not in ("", "identity"):
            # The upstream ignored Accept-Encoding: identity. Decode what the
            # stdlib can; refuse what it cannot rather than relay ungated bytes.
            raw = resp.read()
            try:
                if encoding in ("gzip", "x-gzip"):
                    raw = zlib.decompress(raw, 16 + zlib.MAX_WBITS)
                elif encoding == "deflate":
                    raw = zlib.decompress(raw)
                else:
                    raise ValueError(encoding)
            except (zlib.error, ValueError):
                self._error(502, f"Decision OS cannot inspect a {encoding}-encoded model response")
                return
            resp = _Body(raw, resp.headers)
        if "text/event-stream" not in ctype:
            data = resp.read()
            try:
                parsed = json.loads(data)
            except ValueError:
                self._error(
                    502,
                    "Decision OS could not parse the model response, so it was not "
                    "delivered (tool calls in it could not be checked)",
                )
                return
            gate = {
                "chat": gate_chat_completion,
                "anthropic": gate_anthropic_message,
                "responses": gate_responses_body,
            }[shape]
            out = json.dumps(gate(parsed, judge), ensure_ascii=False).encode("utf-8")
            self._reply(status, out, ctype, passthrough_headers)
            return
        # streaming: chunked transfer, relayed live until the first tool call
        self.send_response(status)
        for k, v in passthrough_headers:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def write(data: bytes) -> None:
            if data:
                self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()

        streamer = {
            "chat": stream_chat,
            "anthropic": stream_anthropic,
            "responses": stream_responses,
        }[shape]
        try:
            streamer(resp, write, judge)
        finally:
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except OSError:
                pass


def agent_env(
    port: int, *, env: dict[str, str], agent: str
) -> tuple[dict[str, str], dict[str, str]]:
    """Environment for an agent started by ``decision-os run``, plus the upstreams
    it implies (an agent already pointed at a custom base URL keeps that upstream)."""
    base = f"http://127.0.0.1:{port}"
    ups: dict[str, str] = {}
    out = dict(env)
    for var in ("OPENAI_BASE_URL", "OPENAI_API_BASE"):
        if env.get(var) and not env[var].startswith(base):
            ups["openai"] = env[var].rstrip("/")
            break
    if env.get("ANTHROPIC_BASE_URL") and not env["ANTHROPIC_BASE_URL"].startswith(base):
        ups["anthropic"] = env["ANTHROPIC_BASE_URL"].rstrip("/")
    out["OPENAI_BASE_URL"] = f"{base}/u/openai"
    out["OPENAI_API_BASE"] = f"{base}/u/openai"
    out["ANTHROPIC_BASE_URL"] = f"{base}/u/anthropic"
    out["DECISION_OS_LLM_GATEWAY"] = base
    out["DECISION_OS_AGENT"] = agent
    return out, ups


def parse_upstream_override(spec: str) -> tuple[str, str]:
    name, sep, url = spec.partition("=")
    if not sep or not urllib.parse.urlparse(url).scheme.startswith("http"):
        raise ValueError(f"--upstream expects name=https://host/base, got {spec!r}")
    return name.strip(), url.strip().rstrip("/")
