"""The model gateway against a fake upstream speaking OpenAI and Anthropic shapes."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import APPROVED, Approver
from decision_os_min.gateway.llm_proxy import LlmGateway, agent_env, sse_events

# ------------------------------------------------------------------ fixtures


def chat_tool_message():
    return {
        "id": "c1",
        "object": "chat.completion",
        "model": "gpt-x",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "t1",
                            "type": "function",
                            "function": {"name": "get_weather", "arguments": '{"city":"Oulu"}'},
                        },
                        {
                            "id": "t2",
                            "type": "function",
                            "function": {"name": "delete_repo", "arguments": '{"repo":"me/x"}'},
                        },
                    ],
                },
            }
        ],
    }


def chat_stream(allowed_only=False):
    base = {"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-x"}
    ev = [
        {
            **base,
            "choices": [
                {"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}
            ],
        },
        {
            **base,
            "choices": [{"index": 0, "delta": {"content": "Let me check."}, "finish_reason": None}],
        },
        {
            **base,
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "t1",
                                "type": "function",
                                "function": {"name": "get_weather", "arguments": ""},
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ],
        },
        {
            **base,
            "choices": [
                {
                    "index": 0,
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"city":'}}]},
                    "finish_reason": None,
                }
            ],
        },
        {
            **base,
            "choices": [
                {
                    "index": 0,
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"Oulu"}'}}]},
                    "finish_reason": None,
                }
            ],
        },
    ]
    if not allowed_only:
        ev += [
            {
                **base,
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 1,
                                    "id": "t2",
                                    "type": "function",
                                    "function": {
                                        "name": "delete_repo",
                                        "arguments": '{"repo":"me/x"}',
                                    },
                                }
                            ]
                        },
                        "finish_reason": None,
                    }
                ],
            },
        ]
    ev += [
        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
        {**base, "choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 7}},
    ]
    return b"".join(f"data: {json.dumps(e)}\n\n".encode() for e in ev) + b"data: [DONE]\n\n"


def anthropic_message(tool="Bash", tool_input=None):
    return {
        "id": "m1",
        "type": "message",
        "role": "assistant",
        "model": "claude-x",
        "stop_reason": "tool_use",
        "content": [
            {"type": "text", "text": "Cleaning up."},
            {
                "type": "tool_use",
                "id": "tu1",
                "name": tool,
                "input": tool_input or {"command": "rm -rf /"},
            },
        ],
    }


def anthropic_stream(tool="Bash", tool_input='{"command": "rm -rf /"}'):
    def e(t, d):
        return f"event: {t}\ndata: {json.dumps({'type': t, **d})}\n\n".encode()

    half = len(tool_input) // 2
    return b"".join(
        [
            e(
                "message_start",
                {
                    "message": {
                        "id": "m2",
                        "type": "message",
                        "role": "assistant",
                        "content": [],
                        "model": "claude-x",
                        "stop_reason": None,
                    }
                },
            ),
            e("content_block_start", {"index": 0, "content_block": {"type": "text", "text": ""}}),
            e(
                "content_block_delta",
                {"index": 0, "delta": {"type": "text_delta", "text": "On it."}},
            ),
            e("content_block_stop", {"index": 0}),
            e(
                "content_block_start",
                {
                    "index": 1,
                    "content_block": {"type": "tool_use", "id": "tu2", "name": tool, "input": {}},
                },
            ),
            e(
                "content_block_delta",
                {
                    "index": 1,
                    "delta": {"type": "input_json_delta", "partial_json": tool_input[:half]},
                },
            ),
            e("ping", {}),
            e(
                "content_block_delta",
                {
                    "index": 1,
                    "delta": {"type": "input_json_delta", "partial_json": tool_input[half:]},
                },
            ),
            e("content_block_stop", {"index": 1}),
            e(
                "message_delta",
                {"delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 9}},
            ),
            e("message_stop", {}),
        ]
    )


def responses_body():
    return {
        "id": "r1",
        "object": "response",
        "output": [
            {
                "type": "function_call",
                "id": "fc1",
                "call_id": "c1",
                "name": "delete_repo",
                "arguments": '{"repo":"a"}',
            },
            {
                "type": "function_call",
                "id": "fc2",
                "call_id": "c2",
                "name": "get_weather",
                "arguments": '{"city":"Oulu"}',
            },
        ],
    }


def responses_stream():
    out = responses_body()["output"]
    seq = iter(range(100))

    def e(t, d):
        return f"event: {t}\ndata: {json.dumps({'type': t, 'sequence_number': next(seq), **d})}\n\n".encode()

    chunks = [e("response.created", {"response": {"id": "r2", "output": []}})]
    for i, item in enumerate(out):
        chunks += [
            e("response.output_item.added", {"output_index": i, "item": {**item, "arguments": ""}}),
            e(
                "response.function_call_arguments.delta",
                {"output_index": i, "item_id": item["id"], "delta": item["arguments"]},
            ),
            e("response.output_item.done", {"output_index": i, "item": item}),
        ]
    chunks.append(e("response.completed", {"response": {"id": "r2", "output": out}}))
    return b"".join(chunks)


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/models":
            self._send(200, b'{"data":[{"id":"gpt-x"}]}', "application/json")
        else:
            self._send(404, b"{}", "application/json")

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        sc = self.headers.get("X-Scenario", "")
        stream = body.get("stream")
        if self.headers.get("Authorization") != "Bearer k":
            self._send(401, b'{"error":"no key"}', "application/json")
        elif self.path == "/v1/chat/completions" and sc == "custom":
            body = chat_tool_message()
            body["choices"][0]["message"]["tool_calls"] = [
                {"id": "c1", "type": "custom", "custom": {"name": "delete_repo", "input": "me/x"}},
                {"id": "c2", "type": "custom", "custom": {"name": "get_weather", "input": "Oulu"}},
                {"id": "c3", "type": "mystery", "mystery": {"payload": 1}},
            ]
            self._send(200, json.dumps(body).encode(), "application/json")
        elif self.path == "/v1/chat/completions" and sc == "gzip":
            import gzip

            data = gzip.compress(json.dumps(chat_tool_message()).encode())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/v1/chat/completions" and sc == "garbage":
            self._send(200, b"{not json", "application/json")
        elif self.path == "/v1/responses" and sc == "shell":
            body = {
                "id": "r9",
                "object": "response",
                "output": [
                    {
                        "type": "shell_call",
                        "id": "s1",
                        "call_id": "x",
                        "action": {"commands": ["rm -rf /"]},
                    },
                    {"type": "web_search_call", "id": "w1", "status": "completed"},
                ],
            }
            self._send(200, json.dumps(body).encode(), "application/json")
        elif self.path == "/v1/chat/completions":
            if stream:
                self._send(200, chat_stream(sc == "allowed"), "text/event-stream")
            else:
                self._send(200, json.dumps(chat_tool_message()).encode(), "application/json")
        elif self.path == "/v1/messages":
            if sc == "email":
                tool, inp = "send_email", '{"to": "a@b.c", "password": "hunter2"}'
            elif sc == "ls":
                tool, inp = "Bash", '{"command": "ls"}'
            else:
                tool, inp = "Bash", '{"command": "rm -rf /"}'
            if stream:
                self._send(200, anthropic_stream(tool, inp), "text/event-stream")
            else:
                self._send(
                    200,
                    json.dumps(anthropic_message(tool, json.loads(inp))).encode(),
                    "application/json",
                )
        elif self.path == "/v1/responses":
            if stream:
                self._send(200, responses_stream(), "text/event-stream")
            else:
                self._send(200, json.dumps(responses_body()).encode(), "application/json")
        else:
            self._send(404, b"{}", "application/json")


@pytest.fixture
def upstream():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def gw(policy_home, upstream):
    g = LlmGateway(
        policy_home,
        agent="tester",
        interactive=False,
        upstreams={"fake": f"{upstream}/v1", "fakeanthropic": upstream},
    )
    port = g.serve_in_thread()
    yield f"http://127.0.0.1:{port}"
    g.server.shutdown()


def post(url, body, scenario="", key="k"):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "X-Scenario": scenario,
        },
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, r.headers.get("Content-Type"), r.read()


def events(raw):
    import io

    out = []
    for _, _ev, data in sse_events(io.BytesIO(raw)):
        if data and data != "[DONE]":
            out.append(json.loads(data))
        elif data == "[DONE]":
            out.append("[DONE]")
    return out


# --------------------------------------------------------------------- tests


def test_chat_completion_drops_denied_call_keeps_allowed(gw):
    _, _, raw = post(f"{gw}/u/fake/chat/completions", {"model": "gpt-x", "messages": []})
    msg = json.loads(raw)["choices"][0]["message"]
    assert [t["function"]["name"] for t in msg["tool_calls"]] == ["get_weather"]
    assert "Blocked the `delete_repo` tool call" in msg["content"]


def test_chat_stream_rewrites_only_after_the_first_tool_call(gw):
    _, ctype, raw = post(
        f"{gw}/u/fake/chat/completions", {"model": "gpt-x", "stream": True, "messages": []}
    )
    assert "text/event-stream" in ctype
    evs = events(raw)
    assert evs[-1] == "[DONE]"
    chunks = [e for e in evs if e != "[DONE]"]
    text = "".join(
        c["choices"][0]["delta"].get("content") or "" for c in chunks if c.get("choices")
    )
    assert text.startswith("Let me check.") and "Blocked the `delete_repo`" in text
    calls = [
        tc
        for c in chunks
        if c.get("choices")
        for tc in c["choices"][0]["delta"].get("tool_calls") or []
    ]
    assert [(tc["index"], tc["function"]["name"], tc["function"]["arguments"]) for tc in calls] == [
        (0, "get_weather", '{"city":"Oulu"}')
    ]
    finals = [
        c["choices"][0]["finish_reason"]
        for c in chunks
        if c.get("choices") and c["choices"][0]["finish_reason"]
    ]
    assert finals == ["tool_calls"]
    assert any(c.get("usage") for c in chunks)


def test_chat_stream_all_allowed_is_byte_identical(gw):
    _, _, raw = post(
        f"{gw}/u/fake/chat/completions",
        {"model": "gpt-x", "stream": True, "messages": []},
        scenario="allowed",
    )
    assert raw == chat_stream(allowed_only=True)


def test_anthropic_guardrail_blocks_catastrophic_bash(gw):
    _, _, raw = post(f"{gw}/u/fakeanthropic/v1/messages", {"model": "claude-x", "messages": []})
    body = json.loads(raw)
    assert [b["type"] for b in body["content"]] == ["text", "text"]
    assert "Blocked the `Bash` tool call" in body["content"][1]["text"]
    assert body["stop_reason"] == "end_turn"


def test_anthropic_stream_block_and_reindex(gw):
    _, _, raw = post(
        f"{gw}/u/fakeanthropic/v1/messages", {"model": "claude-x", "stream": True, "messages": []}
    )
    evs = events(raw)
    starts = [
        (e["index"], e["content_block"]["type"]) for e in evs if e["type"] == "content_block_start"
    ]
    assert starts == [(0, "text"), (1, "text")]
    note = [e for e in evs if e["type"] == "content_block_delta" and e["index"] == 1][0]
    assert "rm -rf" not in json.dumps([e for e in evs if e["type"] == "content_block_start"])
    assert "catastrophic" in note["delta"]["text"] or "recursive delete" in note["delta"]["text"]
    md = [e for e in evs if e["type"] == "message_delta"][0]
    assert md["delta"]["stop_reason"] == "end_turn" and md["usage"]["output_tokens"] == 9
    assert evs[-1]["type"] == "message_stop"


def test_anthropic_stream_limit_rewrites_arguments(gw):
    _, _, raw = post(
        f"{gw}/u/fakeanthropic/v1/messages",
        {"model": "claude-x", "stream": True, "messages": []},
        scenario="email",
    )
    evs = events(raw)
    deltas = "".join(
        e["delta"]["partial_json"]
        for e in evs
        if e["type"] == "content_block_delta" and e["delta"]["type"] == "input_json_delta"
    )
    assert json.loads(deltas) == {"to": "a@b.c", "password": "[REDACTED]"}
    md = [e for e in evs if e["type"] == "message_delta"][0]
    assert md["delta"]["stop_reason"] == "tool_use"


def test_responses_non_stream_and_stream(gw):
    _, _, raw = post(f"{gw}/u/fake/responses", {"model": "gpt-x", "input": "x"})
    out = json.loads(raw)["output"]
    assert [i.get("name") or i["type"] for i in out] == ["get_weather", "message"]
    _, _, raw = post(f"{gw}/u/fake/responses", {"model": "gpt-x", "input": "x", "stream": True})
    evs = events(raw)
    done = [e for e in evs if e["type"] == "response.output_item.done"]
    assert [(e["output_index"], e["item"]["type"], e["item"].get("name")) for e in done] == [
        (0, "function_call", "get_weather"),
        (1, "message", None),
    ]
    assert all(
        e.get("output_index") != 1 or e["item"]["type"] == "message"
        for e in evs
        if e["type"].startswith("response.output_item")
    )
    completed = [e for e in evs if e["type"] == "response.completed"][0]
    assert [i["type"] for i in completed["response"]["output"]] == ["function_call", "message"]
    seqs = [e["sequence_number"] for e in evs]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_passthrough_and_errors(gw):
    with urllib.request.urlopen(
        urllib.request.Request(f"{gw}/u/fake/models", headers={"Authorization": "Bearer k"})
    ) as r:
        assert json.loads(r.read()) == {"data": [{"id": "gpt-x"}]}
    with pytest.raises(urllib.error.HTTPError) as exc:
        post(f"{gw}/u/fake/chat/completions", {"model": "gpt-x"}, key="wrong")
    assert exc.value.code == 401
    with pytest.raises(urllib.error.HTTPError) as exc:
        post(f"{gw}/u/nope/chat/completions", {})
    assert exc.value.code == 404


def test_interactive_approval_through_the_model_gateway(policy_home, upstream):
    g = LlmGateway(policy_home, agent="tester", upstreams={"fakeanthropic": upstream})
    port = g.serve_in_thread()
    try:
        # a harmless Bash call: the balanced profile asks, the human approves
        with Approver(policy_home, APPROVED) as ap:
            _, _, raw = post(
                f"http://127.0.0.1:{port}/u/fakeanthropic/v1/messages",
                {"model": "claude-x", "messages": []},
                scenario="ls",
            )
        body = json.loads(raw)
        assert [b["type"] for b in body["content"]] == ["text", "tool_use"]
        assert ap.seen and ap.seen[0]["server"] == "llm" and ap.seen[0]["model"] == "claude-x"
    finally:
        g.server.shutdown()


def test_agent_env_keeps_custom_upstreams():
    env, ups = agent_env(9999, env={"OPENAI_BASE_URL": "http://localhost:11434/v1"}, agent="aider")
    assert env["OPENAI_BASE_URL"] == "http://127.0.0.1:9999/u/openai"
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:9999/u/anthropic"
    assert ups == {"openai": "http://localhost:11434/v1"}


def test_custom_and_unknown_chat_tool_calls(gw):
    _, _, raw = post(
        f"{gw}/u/fake/chat/completions", {"model": "gpt-x", "messages": []}, scenario="custom"
    )
    msg = json.loads(raw)["choices"][0]["message"]
    assert [(t["type"], t["custom"]["name"]) for t in msg["tool_calls"]] == [
        ("custom", "get_weather")
    ]
    assert "delete_repo" in msg["content"] and "unrecognized format" in msg["content"]


def test_gzip_upstream_is_decoded_and_gated(gw):
    _, _, raw = post(
        f"{gw}/u/fake/chat/completions", {"model": "gpt-x", "messages": []}, scenario="gzip"
    )
    msg = json.loads(raw)["choices"][0]["message"]
    assert [t["function"]["name"] for t in msg["tool_calls"]] == ["get_weather"]


def test_unparseable_model_response_is_not_delivered(gw):
    with pytest.raises(urllib.error.HTTPError) as exc:
        post(
            f"{gw}/u/fake/chat/completions", {"model": "gpt-x", "messages": []}, scenario="garbage"
        )
    assert exc.value.code == 502


def test_responses_shell_call_is_gated_server_tools_pass(gw):
    _, _, raw = post(f"{gw}/u/fake/responses", {"model": "gpt-x", "input": "x"}, scenario="shell")
    out = json.loads(raw)["output"]
    assert [i["type"] for i in out] == ["web_search_call", "message"]
    assert "recursive delete" in out[1]["content"][0]["text"]


def test_streamed_custom_tool_calls(policy_home):
    import io

    from decision_os_min.gateway.engine import Gateway
    from decision_os_min.gateway.llm_proxy import ToolCallJudge, stream_chat

    base = {"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "gpt-x"}

    def ch(delta, fin=None):
        return f"data: {json.dumps({**base, 'choices': [{'index': 0, 'delta': delta, 'finish_reason': fin}]})}\n\n"

    raw = (
        "".join(
            [
                ch(
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "a",
                                "type": "custom",
                                "custom": {"name": "get_weather", "input": "Ou"},
                            }
                        ],
                    }
                ),
                ch({"tool_calls": [{"index": 0, "custom": {"input": "lu"}}]}),
                ch(
                    {
                        "tool_calls": [
                            {
                                "index": 1,
                                "id": "b",
                                "type": "custom",
                                "custom": {"name": "delete_repo", "input": "me/x"},
                            }
                        ]
                    }
                ),
                ch({}, "tool_calls"),
            ]
        ).encode()
        + b"data: [DONE]\n\n"
    )
    out: list[bytes] = []
    judge = ToolCallJudge(Gateway(client="t", home=policy_home, interactive=False), "gpt-x")
    stream_chat(io.BytesIO(raw), out.append, judge)
    evs = [e for e in events(b"".join(out)) if e != "[DONE]"]
    calls = [tc for e in evs for tc in e["choices"][0]["delta"].get("tool_calls") or []]
    assert calls == [
        {
            "index": 0,
            "id": "a",
            "type": "custom",
            "custom": {"name": "get_weather", "input": "Oulu"},
        }
    ]
    assert evs[0]["choices"][0]["delta"]["role"] == "assistant"
    assert any("delete_repo" in (e["choices"][0]["delta"].get("content") or "") for e in evs)
