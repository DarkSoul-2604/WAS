const attackGroupsEl = document.getElementById("attack-groups");
const wafToggleBtn = document.getElementById("waf-toggle");
const wafStateLabel = document.getElementById("waf-toggle-state");
const backendDot = document.getElementById("backend-dot");
const backendLabel = document.getElementById("backend-label");
const resetBtn = document.getElementById("reset-btn");

const logTable = document.getElementById("log-table");
const logBody = document.getElementById("log-body");
const logEmpty = document.getElementById("log-empty");

const mTotal = document.getElementById("m-total");
const mBlocked = document.getElementById("m-blocked");
const mAllowed = document.getElementById("m-allowed");
const mRate = document.getElementById("m-rate");

let knownLogCount = 0;
let currentWafEnabled = true;

// ---------------------------------------------------------------
// Flow diagram animation
// ---------------------------------------------------------------
const packet1 = document.getElementById("packet-1");
const packet2 = document.getElementById("packet-2");
const iconWaf = document.getElementById("icon-waf");
const iconBackend = document.getElementById("icon-backend");
const wafSub = document.getElementById("waf-sub");

function movePacket(el, ms) {
  return new Promise((resolve) => {
    el.style.transition = "none";
    el.style.left = "0%";
    el.style.opacity = "1";
    void el.offsetWidth; // force reflow so the next transition actually animates
    requestAnimationFrame(() => {
      el.style.transition = `left ${ms}ms linear`;
      el.style.left = "100%";
    });
    setTimeout(() => {
      el.style.opacity = "0";
      resolve();
    }, ms);
  });
}

function resetFlowVisuals() {
  iconWaf.classList.remove("flash-block", "flash-allow");
  iconBackend.classList.remove("flash-block", "flash-allow");
  wafSub.textContent = currentWafEnabled ? "Protection on" : "Protection off";
}

async function animateFlow(outcome) {
  // outcome: { blocked: bool, reason: string|null, mixed: bool }
  resetFlowVisuals();
  await movePacket(packet1, 420);

  if (outcome.blocked) {
    iconWaf.classList.add("flash-block");
    wafSub.textContent = outcome.reason ? `Blocked · ${outcome.reason}` : "Blocked";
  } else {
    iconWaf.classList.add(outcome.mixed ? "flash-block" : "flash-allow");
    wafSub.textContent = outcome.mixed ? "Partly blocked" : "Passed through";
    await movePacket(packet2, 420);
    iconBackend.classList.add(outcome.mixed ? "flash-allow" : "flash-allow");
  }

  setTimeout(resetFlowVisuals, 2800);
}

// ---------------------------------------------------------------
// Plain-language narrative for the result panel
// ---------------------------------------------------------------
const REASON_EXPLANATIONS = {
  SQLI_SIGNATURE: "The WAF spotted a known SQL-injection pattern (a comment marker like -- or /*, or a tautology like OR 1=1) and rejected the request before the backend ever saw it.",
  XSS_SIGNATURE: "The WAF spotted script-like content — a <script> tag or an inline event handler such as onerror= — and rejected the request before it could be reflected back into a page.",
  PATH_TRAVERSAL_SIGNATURE: "The WAF spotted a '../' style pattern trying to climb out of the intended folder and rejected the request.",
  RATE_LIMIT: "Too many requests came from this address too quickly, so the WAF started throttling them regardless of content.",
  OVERSIZED_PAYLOAD: "The request body was bigger than the WAF allows, so it was rejected outright without even inspecting the content.",
};

function narrate(attack, result) {
  if (result.ok === false) {
    return "The request couldn't complete — check that all three servers (backend, WAF, dashboard) are running.";
  }

  const preview = (result.response_preview || "").toLowerCase();

  if (result.blocked) {
    return REASON_EXPLANATIONS[result.reason] || "The WAF rejected this request.";
  }

  // Allowed through — say whether it actually achieved anything.
  if (attack.category.startsWith("SQL") && preview.includes("'role': 'admin'")) {
    return "It got through the WAF, and it worked: the backend just logged you in as admin without ever checking a real password.";
  }
  if (attack.category.startsWith("Path traversal") && preview.includes("flag{")) {
    return "It got through the WAF, and it worked: the backend read a file outside its intended folder and handed back its contents.";
  }
  if (attack.id === "path_traversal_double_encoded") {
    return "It got past the WAF's detection — that's a real bypass. But the backend here only decodes a path once too, so this particular payload didn't resolve to the flag file. The WAF missed it; the exploit still didn't land.";
  }
  if (attack.category.startsWith("XSS")) {
    return "It got through. The tag was reflected straight back into the page unescaped — in a real browser this would execute.";
  }
  if (attack.category === "Volumetric") {
    return `It got through. The backend responded normally (HTTP ${result.status_code}).`;
  }
  return `It got through the WAF and reached the backend, which responded with HTTP ${result.status_code}.`;
}

function renderResultPanel(attack, resultForNarrative, rawObj) {
  const panel = document.getElementById("result-panel");
  const nameEl = document.getElementById("result-attack-name");
  const pillEl = document.getElementById("result-verdict-pill");
  const narrativeEl = document.getElementById("result-narrative");
  const rawEl = document.getElementById("result-raw-pre");

  panel.hidden = false;
  nameEl.textContent = `${attack.category} — ${attack.name}`;

  let pillClass = "allowed";
  let pillText = "Allowed";
  if (resultForNarrative.mixed) { pillClass = "mixed"; pillText = "Partly blocked"; }
  else if (resultForNarrative.blocked) { pillClass = "blocked"; pillText = "Blocked"; }
  pillEl.className = `result-verdict-pill ${pillClass}`;
  pillEl.textContent = pillText;

  narrativeEl.textContent = narrate(attack, resultForNarrative);
  rawEl.textContent = `Payload: ${attack.payload}\n\n` + JSON.stringify(rawObj, null, 2);
}

// ---------------------------------------------------------------
// Attack console rendering
// ---------------------------------------------------------------
async function loadAttacks() {
  const res = await fetch("/api/attacks");
  const attacks = await res.json();
  window.__attacksById = Object.fromEntries(attacks.map((a) => [a.id, a]));

  const groups = {};
  attacks.forEach((a) => {
    if (!groups[a.category]) groups[a.category] = [];
    groups[a.category].push(a);
  });

  attackGroupsEl.innerHTML = "";
  Object.entries(groups).forEach(([category, items]) => {
    const groupEl = document.createElement("div");
    groupEl.className = "attack-category";

    const nameEl = document.createElement("div");
    nameEl.className = "attack-category-name";
    nameEl.textContent = category;
    groupEl.appendChild(nameEl);

    items.forEach((a) => {
      const row = document.createElement("div");
      row.className = "attack-row";
      row.innerHTML = `
        <div class="attack-info">
          <div class="attack-name">${a.name}</div>
          <div class="attack-desc">${a.description}</div>
          <div class="attack-payload">${a.payload}</div>
        </div>
        <button class="fire-btn" data-id="${a.id}">Fire</button>
      `;
      groupEl.appendChild(row);
    });

    attackGroupsEl.appendChild(groupEl);
  });

  attackGroupsEl.querySelectorAll(".fire-btn").forEach((btn) => {
    btn.addEventListener("click", () => fireAttack(btn));
  });
}

async function fireAttack(btn) {
  const id = btn.dataset.id;
  const attack = window.__attacksById[id];
  const originalText = "Fire";
  btn.disabled = true;
  btn.textContent = "Firing…";
  btn.classList.remove("result-blocked", "result-allowed");

  let data;
  try {
    const res = await fetch("/api/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    data = await res.json();
  } catch (e) {
    data = { ok: false };
  }

  let outcome;
  if (data.burst) {
    outcome = { blocked: data.blocked_count === data.count, mixed: data.blocked_count > 0 && data.blocked_count < data.count, reason: null };
    btn.textContent = `${data.blocked_count}/${data.count} blocked`;
    btn.classList.add(data.blocked_count > 0 ? "result-blocked" : "result-allowed");
  } else if (data.ok === false) {
    outcome = { blocked: false, mixed: false, reason: null };
    btn.textContent = "Error";
  } else if (data.blocked) {
    outcome = { blocked: true, mixed: false, reason: data.reason };
    btn.textContent = `Blocked (${data.reason || "n/a"})`;
    btn.classList.add("result-blocked");
  } else {
    outcome = { blocked: false, mixed: false, reason: null };
    btn.textContent = `Allowed (${data.status_code})`;
    btn.classList.add("result-allowed");
  }

  renderResultPanel(attack, { ...outcome, response_preview: data.response_preview, status_code: data.status_code, ok: data.ok }, data);
  animateFlow(outcome);
  await loadLogs();

  setTimeout(() => {
    btn.disabled = false;
    btn.textContent = originalText;
    btn.classList.remove("result-blocked", "result-allowed");
  }, 2600);
}

// ---------------------------------------------------------------
// WAF toggle + backend status
// ---------------------------------------------------------------
function applyWafState(enabled) {
  currentWafEnabled = enabled;
  wafToggleBtn.setAttribute("aria-pressed", enabled ? "true" : "false");
  wafStateLabel.textContent = enabled ? "Protection on" : "Protection off";
  wafSub.textContent = enabled ? "Protection on" : "Protection off";
}

async function refreshStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (typeof data.waf_enabled === "boolean") applyWafState(data.waf_enabled);
    backendDot.classList.toggle("up", !!data.backend_up);
    backendDot.classList.toggle("down", !data.backend_up);
    backendLabel.textContent = data.backend_up ? "backend up" : "backend unreachable";
  } catch (e) {
    backendDot.classList.remove("up");
    backendDot.classList.add("down");
    backendLabel.textContent = "dashboard offline";
  }
}

wafToggleBtn.addEventListener("click", async () => {
  wafToggleBtn.disabled = true;
  try {
    const res = await fetch("/api/toggle", { method: "POST" });
    const data = await res.json();
    if (typeof data.enabled === "boolean") applyWafState(data.enabled);
  } finally {
    wafToggleBtn.disabled = false;
  }
});

resetBtn.addEventListener("click", async () => {
  await fetch("/api/reset", { method: "POST" });
  knownLogCount = 0;
  await loadLogs();
});

// ---------------------------------------------------------------
// Live log
// ---------------------------------------------------------------
function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false });
}

async function loadLogs() {
  const res = await fetch("/api/logs?n=150");
  const data = await res.json();
  const entries = data.entries || [];
  const m = data.metrics || {};

  mTotal.textContent = m.total ?? 0;
  mBlocked.textContent = m.blocked ?? 0;
  mAllowed.textContent = m.allowed ?? 0;
  mRate.textContent = `${m.block_rate ?? 0}%`;

  if (entries.length === 0) {
    logEmpty.hidden = false;
    logTable.hidden = true;
    knownLogCount = 0;
    return;
  }
  logEmpty.hidden = true;
  logTable.hidden = false;

  logBody.innerHTML = "";
  entries.forEach((e, idx) => {
    const tr = document.createElement("tr");
    const action = (e.action || "").toLowerCase();
    const pillClass = action === "blocked" ? "blocked" : action === "allowed" ? "allowed" : "error";

    tr.innerHTML = `
      <td>${fmtTime(e.ts)}</td>
      <td><span class="state-pill ${pillClass}">${e.action}${e.reason ? " · " + e.reason : ""}</span></td>
      <td>${e.method}</td>
      <td class="path-cell">${e.path}${e.query ? "?" + e.query : ""}</td>
      <td>${e.waf_enabled ? "on" : "off"}</td>
      <td>${e.status_code ?? "–"}</td>
      <td>${e.latency_ms ?? "–"} ms</td>
    `;

    if (idx === 0 && entries.length > knownLogCount) {
      tr.classList.add(action === "blocked" ? "row-flash-block" : "row-flash-allow");
    }
    logBody.appendChild(tr);
  });

  knownLogCount = entries.length;
}

// ---------------------------------------------------------------
// Boot
// ---------------------------------------------------------------
loadAttacks();
refreshStatus();
loadLogs();
setInterval(refreshStatus, 5000);
setInterval(loadLogs, 4000);
