/* Cybersecurity AI — frontend logic.
   Vanilla JS: chat (SSE streaming), dashboard, terminal, safety viewer,
   character animation driven by the manifest. */

const $ = (sel) => document.querySelector(sel);
const state = {
  charOn: true,
  scale: 90,
  states: { idle: { dir: "idle", frames: 6, fps: 6 } },
  cur: null,
  timer: null,
  mode: "assisted",
};

// ---- navigation ----
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    btn.classList.add("active");
    $("#view-" + btn.dataset.view).classList.add("active");
    if (btn.dataset.view === "dashboard") loadDashboard();
    if (btn.dataset.view === "security") { loadSecurity(); loadFindings(); }
    if (btn.dataset.view === "logs") loadLogs();
    if (btn.dataset.view === "memory") { loadMemory(); loadLearning(); }
    if (btn.dataset.view === "settings") { loadSettings(); }
    if (btn.dataset.view === "scope") { loadScope(); }
  });
});

// ---- helpers ----
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 3200);
}

function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function addMsg(role, content) {
  $("#chat-empty")?.classList.add("hidden");
  const div = document.createElement("div");
  div.className = "msg " + role;
  // escape first — content is untrusted (user paste, tool/OSINT output) —
  // then apply markdown-lite formatting on the already-safe string.
  let safe = esc(content);
  safe = safe.replace(/```(\w*)\n?([\s\S]*?)```/g, (m, lang, code) => "<pre>" + code.trim() + "</pre>");
  div.innerHTML = safe.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\n/g, "<br>");
  $("#messages").appendChild(div);
  $("#messages").scrollTop = $("#messages").scrollHeight;
  return div;
}

$("#chat-empty")?.querySelectorAll(".suggestion-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    $("#chat-input").value = chip.dataset.text;
    $("#chat-input").focus();
  });
});

// ---- character ----
async function loadCharManifest() {
  try {
    const r = await apiFetch("/static/character/states.json");
    state.states = (await r.json()).states;
  } catch {
    console.warn("manifest de personagem indisponível");
  }
}

function charSet(name) {
  if (!state.charOn) return;
  if (!state.states[name]) name = "idle";
  if (state.cur === name) return;
  state.cur = name;
  const s = state.states[name];
  let frame = 1;
  const img = $("#char-img");
  const play = () => {
    img.src = `/static/character/${s.dir}/${s.dir}_${String(frame).padStart(2, "0")}.png`;
    frame = frame >= s.frames ? 1 : frame + 1;
  };
  clearInterval(state.timer);
  play();
  state.timer = setInterval(play, 1000 / s.fps);
  // neon pulse on alert
  const stage = $("#char-stage");
  stage.style.filter = name === "alert" ? "drop-shadow(0 0 14px #f43f5e)" : "";
}

function charSay(text, ms = 2600) {
  const b = $("#char-bubble");
  b.textContent = text;
  b.classList.add("show");
  clearTimeout(state._bubble);
  state._bubble = setTimeout(() => b.classList.remove("show"), ms);
}

// ---- approval modal ----
const pendingState = { action: null, onDecide: null };
function showConfirm(pending) {
  $("#confirm-tool").textContent = `Ferramenta: ${pending.tool}`;
  $("#confirm-summary").textContent = pending.summary || "Executar ação?";
  $("#confirm-modal").classList.remove("hidden");
}
function hideConfirm() {
  $("#confirm-modal").classList.add("hidden");
  pendingState.action = null;
}
async function decideConfirm(approve) {
  if (!pendingState.action) return;
  const { action, onDecide } = pendingState;
  hideConfirm();
  const fn = onDecide;
  pendingState.onDecide = null;
  if (fn) await fn(approve, action);
}

// ---- chat (SSE) ----
async function sendChat() {
  if (chatBusy || !workspaceReady) return;
  const input = $("#chat-input");
  const text = input.value.trim();
  if (!text) return;
  setChatBusy(true);
  const taskId = startTaskUI();
  input.value = "";
  addMsg("user", text);
  charSet("thinking");
  charSay("Analisando…");
  const aiMsg = addMsg("ai", "…");
  let wasCancelled = false;

  const readSSE = async (res) => {
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let acc = "";
    let buf = "";
    const paint = () => {
      aiMsg.textContent = acc;
      aiMsg.innerHTML = esc(acc).replace(/\n/g, "<br>");
      $("#messages").scrollTop = $("#messages").scrollHeight;
    };
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const parts = buf.split("\n\n");
      buf = parts.pop() || "";
      for (const part of parts) {
        const line = part.split("\n").find((l) => l.startsWith("data:"));
        if (!line) continue;
        const data = JSON.parse(line.slice(5));
        if (data.cancelled) wasCancelled = true;
        if (data.progress) document.querySelector("#task-progress").textContent = data.progress;
        if (data.error) throw new Error(data.error);
        if (typeof data.content !== "string") continue; // done/keepalive
        acc = data.content;
        paint();
        if (data.pending) pendingState.action = data.pending;
      }
    }
    return acc;
  };

  try {
    const res = await apiFetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text, task_id: taskId }),
    });
    if (!res.ok) throw new Error("erro " + res.status);
    await readSSE(res);
    await stopTaskUI();

    if (pendingState.action) {
      // a ação aguarda a decisão humana
      charSet("alert");
      charSay("Preciso de autorização.");
      const action = pendingState.action;
      await new Promise((resolve) => {
        pendingState.onDecide = async (approve) => {
          const approvalTask = approve ? startTaskUI() : null;
          try {
            const r = await apiFetch(`/api/actions/${action.id}/${approve ? "approve" : "deny"}${approvalTask ? "?task_id=" + approvalTask : ""}`, {
              method: "POST",
            });
            const d = await r.json();
            if (!r.ok) throw new Error(d.detail || "falha na decisão");
            aiMsg.textContent = d.content || "(sem resposta)";
            aiMsg.innerHTML = esc(aiMsg.textContent).replace(/\n/g, "<br>");
            $("#messages").scrollTop = $("#messages").scrollHeight;
            charSet("talking");
            charSay(d.status === "cancelled" ? "Execução cancelada." : (approve ? "Execução encerrada." : "Ação negada."));
            setTimeout(() => charSet("idle"), 2400);
          } catch (err) {
            toast("Decisão: " + err.message);
          }
          if (approvalTask) await stopTaskUI();
          resolve();
        };
        showConfirm(action);
      });
      pendingState.onDecide = null;
      return;
    }

    charSet("talking");
    charSay(wasCancelled ? "Execução cancelada." : "Pronto!");
    setTimeout(() => charSet("idle"), 2400);
  } catch (err) {
    aiMsg.textContent = "⚠️ " + err.message;
    charSet("alert");
    charSay("Ops, deu erro.");
    setTimeout(() => charSet("idle"), 3000);
  } finally {
    await stopTaskUI();
    setChatBusy(false);
  }
}

// ---- terminal ----
async function termExec() {
  const input = $("#term-input");
  const cmd = input.value.trim();
  if (!cmd) return;
  input.value = "";
  const out = $("#term-out");
  out.textContent += "\n$ " + cmd + "\n";

  try {
    const r = await apiFetch("/api/terminal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: cmd }),
    });
    const data = await r.json();
    if (!r.ok) {
      out.textContent += (data.detail || "erro") + "\n";
    } else if (data.status === "confirm") {
      out.textContent += "⚠️ Requer confirmação. (confirmação humana ainda não habilitada na UI)\n";
    } else if (data.status === "denied") {
      out.textContent += "⛔ Bloqueado pelo Safety Layer.\n";
    } else {
      out.textContent += (data.output || "(sem saída)") + "\n";
    }
  } catch (err) {
    out.textContent += "⚠️ " + err.message + "\n";
  }
  out.scrollTop = out.scrollHeight;
}

// ---- dashboard ----
function updateAlertBadge(n) {
  $("#dash-alerts").textContent = n === 0 ? "🟢 0" : "🟡 " + n;
  $("#dash-alerts").style.color = n === 0 ? "var(--ok)" : "var(--warn)";
  const badge = $("#nav-alert-badge");
  badge.textContent = n;
  badge.classList.toggle("hidden", n === 0);
}

async function loadDashboard() {
  try {
    const r = await apiFetch("/api/system");
    const d = await r.json();
    $("#dash-mem-detail").textContent = d.memory;
    $("#dash-disk-detail").textContent = d.disk;
    const counts = d.alerts || {};
    updateAlertBadge(Object.values(counts).reduce((a, b) => a + b, 0));
    $("#dash-mem").textContent = d.mem_percent != null ? d.mem_percent + "%" : "—";
    $("#dash-disk").textContent = d.disk_percent != null ? d.disk_percent + "%" : "—";
    $("#dash-cpu").textContent = d.cpu_percent != null ? d.cpu_percent + "%" : "—";
  } catch (err) {
    toast("Dashboard: " + err.message);
  }
  loadAlertsList();
}

const _SEVERITY_ICON = { high: "🔴", medium: "🟡", low: "🔵" };

async function loadAlertsList() {
  try {
    const r = await apiFetch("/api/alerts");
    const d = await r.json();
    $("#alerts-list").innerHTML = d.alerts.length
      ? d.alerts.map((a) => `
          <div class="tool alert-item${a.acknowledged ? " acked" : ""}">
            <div class="alert-item-head">
              ${_SEVERITY_ICON[a.severity] || "⚪"} <b>${esc(a.title)}</b>
              <span class="muted"> · ${esc(a.created_at.slice(0, 16).replace("T", " "))}</span>
              ${a.acknowledged ? "" : `<button class="btn ghost alert-ack" data-id="${a.id}">Reconhecer</button>`}
            </div>
            <div class="muted alert-item-desc">${esc(a.description)}</div>
          </div>`).join("")
      : `<p class="muted">Nenhum alerta registrado ainda.</p>`;
    $("#alerts-list").querySelectorAll(".alert-ack").forEach((btn) => {
      btn.addEventListener("click", () => ackAlert(btn.dataset.id));
    });
  } catch (err) {
    toast("Alertas: " + err.message);
  }
}

async function ackAlert(id) {
  try {
    const r = await apiFetch("/api/alerts/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: Number(id) }),
    });
    if (!r.ok) throw new Error("falha ao reconhecer");
    loadDashboard();
  } catch (err) {
    toast("Alertas: " + err.message);
  }
}

// ---- security ----
const _CATEGORY_ORDER = [
  "ofensivo", "exploração", "web", "engenharia-reversa", "osint", "burp",
  "cripto", "rede", "sistema", "diagnóstico", "relatório", "memória", "geral",
];

async function loadSecurity() {
  try {
    const r = await apiFetch("/api/tools");
    const d = await r.json();
    const groups = {};
    for (const t of d.tools) (groups[t.category] || (groups[t.category] = [])).push(t);
    const cats = Object.keys(groups).sort((a, b) => {
      const ia = _CATEGORY_ORDER.indexOf(a), ib = _CATEGORY_ORDER.indexOf(b);
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
    });
    $("#tools-list").innerHTML = cats.map((cat) => `
      <div class="tool-group">
        <div class="tool-group-title">${esc(cat)}</div>
        ${groups[cat].map((t) => `<div class="tool"><b>${esc(t.name)}</b> · ${esc(t.description)} <span class="muted">[risco: ${t.risk}]</span></div>`).join("")}
      </div>`).join("");
  } catch (err) {
    toast("Ferramentas: " + err.message);
  }
}

// ---- memória longa & aprendizado ----
async function loadMemory() {
  try {
    const r = await apiFetch("/api/memory");
    const d = await r.json();
    $("#memory-list").innerHTML = d.facts.length
      ? d.facts.map((f) => `
          <div class="tool">
            <b>${esc(f.content)}</b>
            <span class="muted"> · ${esc(f.created_at.slice(0, 10))}</span>
            <button class="btn ghost fact-del" data-id="${f.id}" title="Esquecer">🗑</button>
          </div>`).join("")
      : `<p class="muted">Nenhum fato guardado ainda.</p>`;
    $("#memory-list").querySelectorAll(".fact-del").forEach((btn) => {
      btn.addEventListener("click", () => forgetMemory(btn.dataset.id));
    });
  } catch (err) {
    toast("Memória: " + err.message);
  }
}

async function forgetMemory(id) {
  try {
    const r = await apiFetch(`/api/memory/${id}`, { method: "DELETE" });
    if (!r.ok) throw new Error("falha ao esquecer");
    loadMemory();
  } catch (err) {
    toast("Memória: " + err.message);
  }
}

async function loadLearning() {
  try {
    const r = await apiFetch("/api/learning/progress");
    const d = await r.json();
    $("#learning-list").innerHTML = d.progress.length
      ? d.progress.map((p) => `
          <div class="tool">
            <b>${esc(p.concept)}</b>
            <span class="muted"> · perguntado ${p.times_asked}x · última vez ${esc(p.last_seen.slice(0, 10))}</span>
          </div>`).join("")
      : `<p class="muted">Nenhum conceito estudado ainda — pergunte "explica X" ou "o que é X" no chat.</p>`;
  } catch (err) {
    toast("Aprendizado: " + err.message);
  }
}

// ---- logs ----
async function loadLogs() {
  try {
    const r = await apiFetch("/api/security/events");
    const d = await r.json();
    $("#events-out").textContent = d.events.length
      ? d.events.map((e) => `[${e.level.toUpperCase()}] ${e.category} — ${e.description}`).join("\n")
      : "(sem eventos)";
  } catch (err) {
    toast("Logs: " + err.message);
  }
}

// ---- settings ----
async function loadSettings() {
  try {
    const r = await apiFetch("/api/health");
    const d = await r.json();
    const research = d.research_provider
      ? `<div class="tool"><b>Research</b> · ${esc(d.research_provider)} / ${esc(d.research_model || "?")}
          <span class="muted">[2° modelo, só planejamento/validação]</span></div>`
      : `<div class="tool muted">Research provider: não configurado (usa o mesmo modelo pra tudo).</div>`;
    $("#settings-providers").innerHTML = `
      <div class="tool"><b>Execução</b> · ${esc(d.provider)} / ${esc(d.model)}
        <span class="muted">[decide e roda ferramentas]</span></div>
      ${research}`;
    $("#set-mode").value = d.safe_mode;
    state.mode = d.safe_mode;
  } catch (err) {
    toast("Configurações: " + err.message);
  }
  loadResearchProviderConfig();
}

// ---- research provider (2° modelo, opcional — host/modelo/chave configuráveis na UI) ----
async function loadResearchProviderConfig() {
  try {
    const r = await apiFetch("/api/provider/research");
    const d = await r.json();
    const select = $("#provider-select");
    select.innerHTML = `<option value="">(nenhum — usa só o principal)</option>` +
      d.available_providers.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");
    select.value = d.provider || "";
    $("#provider-base-url").value = d.base_url || "";
    $("#provider-model").value = d.model || "";
    $("#provider-api-key").value = "";
    const sourceLabel = { ui: "configurado na UI", env: "configurado no .env", none: "nenhum (usa só o principal)" };
    $("#provider-status").textContent =
      `Ativo agora: ${d.provider || "—"} (${sourceLabel[d.source] || d.source})` +
      (d.api_key_set ? " · chave salva" : "");
  } catch (err) {
    toast("Research provider: " + err.message);
  }
}

$("#provider-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    provider: $("#provider-select").value,
    base_url: $("#provider-base-url").value.trim(),
    model: $("#provider-model").value.trim(),
  };
  const key = $("#provider-api-key").value.trim();
  if (key) body.api_key = key;
  try {
    const r = await apiFetch("/api/provider/research", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error((await r.json()).detail || "falha ao salvar");
    toast(body.provider ? `Research provider aplicado: ${body.provider}` : "Research provider removido.");
    loadResearchProviderConfig();
  } catch (err) {
    toast("Research provider: " + err.message);
  }
});

// ---- escopo autorizado ----
let scopeLoadVersion = 0;
async function loadScope() {
  const version = ++scopeLoadVersion;
  $("#scope-input").disabled = true;
  $("#scope-form button").disabled = true;
  try {
    const r = await apiFetch("/api/scope");
    const d = await r.json();
    if (version !== scopeLoadVersion) return;
    $("#scope-input").value = d.scope.join("\n");
    $("#scope-list").innerHTML = d.scope.length
      ? d.scope.map((p) => `<div class="tool">${esc(p)}</div>`).join("")
      : `<p class="muted">Sem escopo definido — ferramentas ofensivas rodam contra qualquer alvo.</p>`;
  } catch (err) {
    toast("Escopo: " + err.message);
  } finally {
    if (version === scopeLoadVersion) {
      $("#scope-input").disabled = false;
      $("#scope-form button").disabled = false;
    }
  }
}

$("#scope-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const patterns = $("#scope-input").value
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
  try {
    const r = await apiFetch("/api/scope", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope: patterns }),
    });
    if (!r.ok) throw new Error("falha ao salvar");
    toast(patterns.length ? `Escopo salvo (${patterns.length} alvo(s)).` : "Escopo limpo — sem restrição.");
    loadScope();
  } catch (err) {
    toast("Escopo: " + err.message);
  }
});

$("#set-char").addEventListener("change", (e) => {
  state.charOn = e.target.checked;
  $("#character").style.display = state.charOn ? "" : "none";
});
$("#set-scale").addEventListener("input", (e) => {
  state.scale = +e.target.value;
  $("#char-stage").style.width = state.scale + "px";
});
$("#set-mode").addEventListener("change", (e) => {
  state.mode = e.target.value;
  toast("Modo: " + state.mode.toUpperCase());
});

// ---- drag to move the character (double-click toggles interactivity) ----
const charEl = $("#character");
let dragging = false, offX = 0, offY = 0;
charEl.addEventListener("dblclick", () => {
  state.charOn = !state.charOn;
  charEl.style.display = state.charOn ? "" : "none";
});
charEl.addEventListener("pointerdown", (e) => {
  charEl.classList.add("draggable");
  dragging = true;
  const r = charEl.getBoundingClientRect();
  offX = e.clientX - r.left;
  offY = e.clientY - r.top;
});
window.addEventListener("pointermove", (e) => {
  if (!dragging) return;
  charEl.style.left = e.clientX - offX + "px";
  charEl.style.right = "auto";
  charEl.style.top = e.clientY - offY + "px";
  charEl.style.bottom = "auto";
});
window.addEventListener("pointerup", () => {
  dragging = false;
  charEl.classList.remove("draggable");
});

// ---- voice PTT (botão de mic) ----
let mediaRec = null, micChunks = [], micActive = false;
const micBtn = $("#mic-btn");

async function micStart() {
  if (micActive) return;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, sampleRate: 16000 } });
    micChunks = [];
    mediaRec = new MediaRecorder(stream, { mimeType: pickMime() });
    mediaRec.ondataavailable = (e) => { if (e.data.size) micChunks.push(e.data); };
    mediaRec.onstop = async () => {
      stream.getTracks().forEach((t) => t.stop());
      const blob = new Blob(micChunks, { type: mediaRec.mimeType });
      if (blob.size < 1000) return;
      try {
        charSet("thinking"); charSay("Transcrevendo…");
        const fd = new FormData();
        fd.append("file", blob, "voice.webm");
        const r = await apiFetch("/api/audio/transcribe", { method: "POST", body: fd });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || "STT falhou");
        if (d.text && d.text.trim()) {
          $("#chat-input").value = d.text;
          sendChat();          // dispara o chat com o texto transcrito
        }
      } catch (err) {
        toast("Voz: " + err.message);
        charSet("alert"); charSay("Ops…");
        setTimeout(() => charSet("idle"), 2500);
      }
    };
    mediaRec.start();
    micActive = true;
    micBtn.classList.add("rec");
    charSet("listening"); charSay("Ouvindo…");
  } catch (err) {
    toast("Mic: " + err.message);
  }
}

function micStop() {
  if (!micActive || !mediaRec) return;
  micActive = false;
  micBtn.classList.remove("rec");
  mediaRec.stop();
}

function pickMime() {
  const opts = ["audio/webm;codecs=opus", "audio/webm", "audio/ogg;codecs=opus"];
  for (const m of opts) if (MediaRecorder.isTypeSupported(m)) return m;
  return "";
}

micBtn.addEventListener("pointerdown", (e) => { e.preventDefault(); micStart(); });
window.addEventListener("pointerup", micStop);

// ---- bind ----
$("#chat-form").addEventListener("submit", (e) => { e.preventDefault(); sendChat(); });
$("#term-form").addEventListener("submit", (e) => { e.preventDefault(); termExec(); });
$("#classify-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const cmd = $("#classify-input").value.trim();
  if (!cmd) return;
  try {
    const r = await apiFetch("/api/safety/classify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "command:" + cmd, risk: "moderate" }),
    });
    const d = await r.json();
    $("#classify-result").textContent =
      `decisão: ${d.decision}\nclassificação do comando: ${d.command}`;
  } catch (err) {
    $("#classify-result").textContent = "erro: " + err.message;
  }
});
$("#memory-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#memory-input");
  const content = input.value.trim();
  if (!content) return;
  input.value = "";
  try {
    const r = await apiFetch("/api/memory", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
    if (!r.ok) throw new Error((await r.json()).detail || "falha ao guardar");
    loadMemory();
  } catch (err) {
    toast("Memória: " + err.message);
  }
});
$("#btn-clear").addEventListener("click", () => {
  $("#messages").querySelectorAll(".msg").forEach((m) => m.remove());
  $("#chat-empty")?.classList.remove("hidden");
  charSay("Conversa limpa!");
});
$("#confirm-approve").addEventListener("click", () => decideConfirm(true));
$("#confirm-deny").addEventListener("click", () => decideConfirm(false));
$("#confirm-modal").addEventListener("click", (e) => {
  if (e.target === $("#confirm-modal")) decideConfirm(false); // clique fora = nega
});

// ---- boot ----
(async function boot() {
  await loadProjects();
  await loadProjectHistory();
  await loadCharManifest();
  charSet("idle");
  charSay("Olá! Sou o Cyber. Pergunte sobre sua rede ou sistema.");
  try {
    const r = await apiFetch("/api/health");
    const d = await r.json();
    const full = `${d.provider} / ${d.model} · ${d.safe_mode}`;
    $("#model-badge").textContent = `${d.provider} · ${d.safe_mode}`;
    $("#model-badge").title = full;
  } catch {
    $("#model-badge").textContent = "backend offline";
  }
  $("#character").style.display = state.charOn ? "" : "none";
  $("#char-stage").style.width = state.scale + "px";
  loadDashboard();  // aba inicial ativa — sem isso ficava com placeholders até trocar de aba
})();
