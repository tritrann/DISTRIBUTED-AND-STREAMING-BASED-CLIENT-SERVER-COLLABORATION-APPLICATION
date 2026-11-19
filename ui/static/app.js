// Web UI (Step 9): plain JavaScript in the browser, no framework.
// It talks only to the local HTTP gateway (ui/gateway.py) with fetch():
// log in, poll for new events every 500 ms, send messages and files.

const state = { token: null, me: null, since: 0, target: "*", transfers: {}, polling: false };
const $ = (id) => document.getElementById(id);

async function api(path, body) {
  const options = { headers: { "X-Token": state.token || "" } };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const res = await fetch(path, options);
  if (res.status === 401) { showLogin("Session ended, please log in again."); throw new Error("401"); }
  return res.json();
}

// ---------- login / logout ----------

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("login-error").textContent = "Connecting...";
  try {
    const r = await api("/api/login", {
      host: $("host").value.trim(), port: Number($("port").value),
      username: $("username").value.trim(), password: $("password").value,
    });
    if (!r.ok) { $("login-error").textContent = r.error; return; }
    state.token = r.token; state.me = r.username; state.since = 0;
    $("password").value = ""; $("login-error").textContent = "";
    $("messages").innerHTML = "";
    $("login-view").hidden = true; $("chat-view").hidden = false;
    $("text").focus();
    if (!state.polling) poll();
  } catch (err) {
    $("login-error").textContent = "Gateway not reachable.";
  }
});

$("logout").addEventListener("click", async () => {
  try { await api("/api/logout", {}); } catch (e) { /* already gone */ }
  showLogin("");
});

function showLogin(message) {
  state.token = null;
  $("chat-view").hidden = true; $("login-view").hidden = false;
  $("login-error").textContent = message;
}

// ---------- polling ----------

async function poll() {
  state.polling = true;
  while (state.token) {
    try {
      const r = await api(`/api/poll?since=${state.since}`);
      for (const ev of r.events) { handleEvent(ev); state.since = ev.seq; }
      renderUsers(r.peers, r.users);
      renderStatus(r);
    } catch (err) {
      if (err.message === "401") break;
      renderStatus({ connected: false, server: "gateway not reachable" });
    }
    await new Promise((ok) => setTimeout(ok, 500));
  }
  state.polling = false;
}

function handleEvent(ev) {
  switch (ev.type) {
    case "message": addMessage(ev.from, ev.to, ev.text, ev.ts); break;
    case "join": addNotice(`${ev.username} joined`); break;
    case "leave": addNotice(`${ev.username} left`); break;
    case "error": addNotice(ev.reason, true); break;
    case "disconnected": addNotice(`Disconnected: ${ev.reason}`, true); break;
    case "file_start":
      state.transfers[ev.file_id] = { ...ev, done: 0, status: "running" };
      renderTransfers(); break;
    case "file_progress":
      if (state.transfers[ev.file_id]) { state.transfers[ev.file_id].done = ev.done; renderTransfers(); }
      break;
    case "file_done": {
      const t = state.transfers[ev.file_id];
      if (t) { t.status = ev.ok ? "done" : "failed"; t.reason = ev.reason; if (ev.ok) t.done = t.size; renderTransfers(); }
      if (ev.ok && ev.direction === "receive") addNotice(`File received from ${t ? t.peer : "?"}: ${t ? t.name : ""}`);
      break;
    }
  }
}

// ---------- rendering ----------

function renderStatus(r) {
  const el = $("status");
  el.className = "status " + (r.connected ? "on" : "off");
  $("status-text").textContent = r.connected ? `${r.username} @ ${r.server}` : `disconnected (${r.server || ""})`;
  if (r.stats) {
    $("stats").textContent = `sent ${r.stats.sent} msg / ${kb(r.stats.bytes_sent)} · received ${r.stats.received} msg / ${kb(r.stats.bytes_received)}`;
  }
}

function renderUsers(peers, users) {
  const list = $("users");
  const items = [{ username: "*", label: "Everyone", sub: "broadcast" }];
  const byName = {};
  for (const p of peers || []) byName[p.username] = p;
  for (const u of users || []) {
    const p = byName[u];
    items.push({ username: u, label: u === state.me ? `${u} (you)` : u, sub: p ? `${p.ip}:${p.port}` : "" });
  }
  if (state.target !== "*" && !(users || []).includes(state.target)) selectTarget("*");
  $("online-count").textContent = (users || []).length;
  list.innerHTML = "";
  for (const it of items) {
    const li = document.createElement("li");
    li.textContent = it.label;
    const small = document.createElement("small");
    small.textContent = it.sub;
    li.appendChild(small);
    if (it.username === state.target) li.className = "selected";
    if (it.username !== state.me) li.addEventListener("click", () => selectTarget(it.username));
    list.appendChild(li);
  }
}

function selectTarget(name) {
  state.target = name;
  $("target").textContent = name === "*" ? "To: everyone" : `To: ${name}`;
  $("text").focus();
}

function addMessage(from, to, text, ts) {
  const box = document.createElement("div");
  box.className = "msg" + (from === state.me ? " mine" : "") + (to !== "*" ? " private" : "");
  const meta = document.createElement("div");
  meta.className = "meta";
  const time = new Date((ts || Date.now() / 1000) * 1000).toLocaleTimeString();
  meta.textContent = from === state.me ? `you → ${to === "*" ? "everyone" : to} · ${time}` : `${from} · ${time}`;
  const body = document.createElement("div");
  body.textContent = text;
  box.append(meta, body);
  appendToChat(box);
}

function addNotice(text, bad) {
  const div = document.createElement("div");
  div.className = "notice" + (bad ? " bad" : "");
  div.textContent = text;
  appendToChat(div);
}

function appendToChat(node) {
  const box = $("messages");
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.appendChild(node);
  if (atBottom) box.scrollTop = box.scrollHeight;
}

function renderTransfers() {
  const list = $("transfers");
  list.innerHTML = "";
  const all = Object.values(state.transfers).reverse();
  if (all.length === 0) { list.innerHTML = '<li class="muted empty">No transfers yet</li>'; return; }
  for (const t of all) {
    const li = document.createElement("li");
    const name = document.createElement("div");
    name.className = "name";
    const left = document.createElement("span");
    left.textContent = `${t.direction === "send" ? "↑" : "↓"} ${t.name}`;
    const right = document.createElement("span");
    const percent = t.size ? Math.floor((t.done * 100) / t.size) : 100;
    right.textContent = `${percent}%`;
    name.append(left, right);
    const bar = document.createElement("progress");
    bar.max = 100; bar.value = percent;
    const info = document.createElement("div");
    info.className = "muted";
    const who = t.direction === "send" ? `to ${t.peer}` : `from ${t.peer}`;
    info.textContent = `${who} · ${kb(t.done)} / ${kb(t.size)}`;
    li.append(name, bar, info);
    if (t.status === "done") {
      const done = document.createElement("div");
      done.className = "done";
      if (t.direction === "receive") {
        const a = document.createElement("a");
        a.href = `/api/download?id=${encodeURIComponent(t.file_id)}&token=${state.token}`;
        a.textContent = "Download (SHA-256 verified)";
        done.appendChild(a);
      } else {
        done.textContent = "Sent";
      }
      li.appendChild(done);
    } else if (t.status === "failed") {
      const fail = document.createElement("div");
      fail.className = "failed";
      fail.textContent = `Failed: ${t.reason}`;
      li.appendChild(fail);
    }
    list.appendChild(li);
  }
}

function kb(n) {
  if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
  if (n >= 1024) return (n / 1024).toFixed(1) + " KB";
  return n + " B";
}

// ---------- sending ----------

$("send-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("text").value.trim();
  if (!text) return;
  $("text").value = "";
  try {
    const r = await api("/api/send", { to: state.target, text });
    if (r.ok) addMessage(state.me, state.target, text, Date.now() / 1000);
    else addNotice(r.error || "not sent", true);
  } catch (err) { /* handled by poll */ }
});

$("file").addEventListener("change", () => {
  const file = $("file").files[0];
  $("file").value = "";
  if (!file) return;
  if (state.target === "*") { addNotice("Pick one user on the left, then send the file.", true); return; }
  const to = state.target;
  const reader = new FileReader();
  reader.onload = async () => {
    const data = reader.result.split(",", 2)[1] || "";   // strip "data:...;base64,"
    try {
      const r = await api("/api/file", { to, name: file.name, data });
      if (!r.ok) addNotice(r.error || "file not sent", true);
    } catch (err) { /* handled by poll */ }
  };
  reader.readAsDataURL(file);
});
