(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const form = $("demo-form");
  const scenarios = {
    support: {
      actor: "agent:support", tool: "send_email", purpose: "support_reply",
      payload: '{"to":"customer@example.test","template":"case_update"}',
      consent: true, capability: true
    },
    payout: {
      actor: "agent:finance", tool: "issue_payout", purpose: "refund",
      payload: '{"account":"acct_demo","amount":25000,"currency":"USD"}',
      consent: true, capability: false
    },
    spoof: {
      actor: "agent:unknown", tool: "deploy_release", purpose: "production_change",
      payload: '{"service":"payments","version":"latest"}',
      consent: false, capability: false
    }
  };
  let lastAllowed = false;

  function applyScenario(name) {
    const value = scenarios[name];
    Object.entries(value).forEach(([key, item]) => {
      const node = $(key);
      if (node.type === "checkbox") node.checked = item;
      else node.value = item;
    });
    resetOutput();
  }

  function resetOutput() {
    $("steps").replaceChildren(stepNode(1, "Waiting for intent", "Choose a scenario and evaluate it."));
    $("status").textContent = "READY";
    $("status").className = "status idle";
    $("decision-card").hidden = true;
    $("replay").disabled = true;
    lastAllowed = false;
  }

  function stepNode(number, title, detail, failed = false) {
    const li = document.createElement("li");
    if (failed) li.className = "fail";
    const marker = document.createElement("span");
    marker.textContent = String(number);
    const copy = document.createElement("div");
    const strong = document.createElement("b");
    const small = document.createElement("small");
    strong.textContent = title;
    small.textContent = detail;
    copy.append(strong, small);
    li.append(marker, copy);
    return li;
  }

  function addStep(number, title, detail, failed = false) {
    $("steps").append(stepNode(number, title, detail, failed));
  }

  const wait = () => new Promise((resolve) => {
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    setTimeout(resolve, reduced ? 0 : 180);
  });

  async function digest(value) {
    if (globalThis.crypto?.subtle) {
      const bytes = new TextEncoder().encode(value);
      const result = await crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(result)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    let fallback = 2166136261;
    for (const char of value) fallback = Math.imul(fallback ^ char.charCodeAt(0), 16777619);
    return `browser-fallback-${(fallback >>> 0).toString(16).padStart(8, "0")}`;
  }

  function finish(verdict, reason, actionDigest) {
    const allowed = verdict === "ALLOW";
    $("status").textContent = verdict;
    $("status").className = `status ${allowed ? "allow" : "deny"}`;
    $("final-verdict").textContent = verdict;
    $("final-reason").textContent = reason;
    $("digest").textContent = `${actionDigest.slice(0, 20)}…`;
    $("decision-card").className = `decision-card${allowed ? "" : " denied"}`;
    $("decision-card").hidden = false;
    lastAllowed = allowed;
    $("replay").disabled = !allowed;
  }

  async function evaluate(event) {
    event.preventDefault();
    form.querySelector('button[type="submit"]').disabled = true;
    $("replay").disabled = true;
    $("decision-card").hidden = true;
    $("steps").replaceChildren();

    const actor = $("actor").value.trim();
    const tool = $("tool").value.trim();
    const purpose = $("purpose").value.trim();
    let payload;
    try {
      payload = JSON.parse($("payload").value);
    } catch {
      addStep(1, "Intent refused", "Payload is not valid JSON.", true);
      finish("DENY", "malformed_intent", "not-computed");
      form.querySelector('button[type="submit"]').disabled = false;
      return;
    }

    const canonical = JSON.stringify({ actor, payload, purpose, tool });
    const actionDigest = await digest(canonical);
    addStep(1, "Intent admitted", `${actor} requests ${tool}.`);
    await wait();

    if (!actor.startsWith("agent:") || actor === "agent:unknown") {
      addStep(2, "Identity refused", "Actor is not bound to this admitted channel.", true);
      finish("DENY", "channel_identity_mismatch", actionDigest);
      form.querySelector('button[type="submit"]').disabled = false;
      return;
    }
    addStep(2, "Identity bound", "Actor matches the admitted Host channel.");
    await wait();

    if (!$("consent").checked) {
      addStep(3, "Legitimacy denied", "Required consent attestation is absent.", true);
      finish("DENY", "legitimacy:missing_consent", actionDigest);
      form.querySelector('button[type="submit"]').disabled = false;
      return;
    }
    addStep(3, "Legitimacy accepted", "No legitimacy evaluator denied the action.");
    await wait();

    if (!$("capability").checked) {
      addStep(4, "Authority denied", `No delegated capability matches ${tool}.`, true);
      finish("DENY", "authority:capability_mismatch", actionDigest);
      form.querySelector('button[type="submit"]').disabled = false;
      return;
    }
    addStep(4, "Authority accepted", `Delegated capability matches ${tool}.`);
    await wait();
    addStep(5, "Decision signed", "Kernel binds the verdict to the canonical action digest.");
    await wait();
    addStep(6, "Token spent; effect audited", "PEP consumes the one-time token before adapter execution.");
    finish("ALLOW", "all_constraints_met", actionDigest);
    form.querySelector('button[type="submit"]').disabled = false;
  }

  async function replay() {
    if (!lastAllowed) return;
    $("replay").disabled = true;
    addStep(7, "Replay refused", "The execution token was already spent atomically.", true);
    await wait();
    $("status").textContent = "DENY";
    $("status").className = "status deny";
    $("final-verdict").textContent = "DENY";
    $("final-reason").textContent = "token_already_spent";
    $("decision-card").className = "decision-card denied";
    lastAllowed = false;
  }

  $("scenario").addEventListener("change", (event) => applyScenario(event.target.value));
  form.addEventListener("submit", evaluate);
  $("replay").addEventListener("click", replay);
})();
