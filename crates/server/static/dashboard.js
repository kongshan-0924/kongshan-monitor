/* 总览(只读):状态卡片 + 汇总 + 搜索/过滤/排序 + 告警高亮 + 卡片自定义 + 版本漂移。
   管理操作(增删改/批量)已移至「服务器」模块。所有动态数据经 textContent 渲染。 */
"use strict";

let NODES = new Map();
let INTERVAL = 5;
let EXPECTED_AGENT = "";

const CARD_MODULES = [
  { id: "cpu", name: "CPU", kind: "meter" },
  { id: "mem", name: "内存", kind: "meter" },
  { id: "disk", name: "磁盘", kind: "meter" },
  { id: "swap", name: "Swap", kind: "meter" },
  { id: "net", name: "网络速率", kind: "foot" },
  { id: "io", name: "磁盘 I/O", kind: "foot" },
  { id: "load", name: "负载", kind: "foot" },
  { id: "procs", name: "进程数", kind: "foot" },
  { id: "uptime", name: "运行时长", kind: "foot" },
];
const DEFAULT_FIELDS = ["cpu", "mem", "disk", "net", "uptime"];
function cardFields() {
  try {
    const v = JSON.parse(localStorage.getItem("op-card-fields") || "null");
    if (Array.isArray(v) && v.length) return v;
  } catch (_) {}
  return DEFAULT_FIELDS.slice();
}
let FIELDS = cardFields();

function pctClass(p) { return p > 90 ? " bad" : p > 70 ? " warn" : ""; }
function meterEl(label, used, total, fmtFn) {
  const p = pct(used, total);
  const wrap = el("div", "meter");
  const lab = el("div", "m-label");
  lab.appendChild(el("span", null, label));
  lab.appendChild(el("span", null, total ? (fmtFn ? fmtFn(used) + " / " + fmtFn(total) : p.toFixed(0) + "%") : "-"));
  const bar = el("div", "m-bar");
  const fill = el("div", "m-fill" + pctClass(p));
  fill.style.width = p.toFixed(1) + "%";
  bar.appendChild(fill);
  wrap.appendChild(lab); wrap.appendChild(bar);
  return wrap;
}
function isOnline(n) {
  if (!n.last_seen) return false;
  return Date.now() / 1000 - n.last_seen <= Math.max(INTERVAL * 3, 10);
}

function moduleNode(id, n, m, online) {
  switch (id) {
    case "cpu": return meterEl("CPU", m.cpu_pct, 100);
    case "mem": return meterEl("内存", m.mem_used, m.mem_total, fmtBytes);
    case "disk": return meterEl("磁盘", m.disk_used, m.disk_total, fmtBytes);
    case "swap": return meterEl("Swap", m.swap_used, m.swap_total, fmtBytes);
    case "net": return el("span", null, "↓ " + fmtBps(m.net_rx_bps) + "  ↑ " + fmtBps(m.net_tx_bps));
    case "io": return el("span", null, "读 " + fmtBps(m.disk_read_bps) + "  写 " + fmtBps(m.disk_write_bps));
    case "load": return el("span", null, "负载 " + m.load1.toFixed(2));
    case "procs": return el("span", null, "进程 " + m.procs);
    case "uptime": return el("span", null, online ? "运行 " + fmtDur(m.uptime_secs) : timeAgo(n.last_seen));
    default: return null;
  }
}

function renderCard(n) {
  const online = isOnline(n);
  const a = el("a", "card node-card" + (n.alerting ? " alerting" : ""));
  a.href = "/nodes/" + encodeURIComponent(n.id);
  a.id = "node-" + n.id;

  const head = el("div", "nc-head");
  const dot = el("span", "dot " + (n.registered ? (online ? "on" : "off") : "pending"));
  dot.title = n.registered ? (online ? "在线" : "离线") : "待注册";
  head.appendChild(dot);
  head.appendChild(el("span", "nc-name", n.name));
  if (n.alerting) head.appendChild(el("span", "nc-alert", "告警"));
  if (n.grp) head.appendChild(el("span", "nc-grp", n.grp));
  a.appendChild(head);

  const osLine = el("div", "nc-os", (n.os || "待接入") + (n.arch ? " · " + n.arch : ""));
  if (n.registered && n.agent_version && EXPECTED_AGENT && n.agent_version !== EXPECTED_AGENT) {
    osLine.appendChild(el("span", "nc-drift", " agent " + n.agent_version + " ↑" + EXPECTED_AGENT));
  }
  a.appendChild(osLine);

  const m = n.latest;
  if (m) {
    const meters = FIELDS.filter((f) => CARD_MODULES.find((x) => x.id === f && x.kind === "meter"));
    const foots = FIELDS.filter((f) => CARD_MODULES.find((x) => x.id === f && x.kind === "foot"));
    for (const f of meters) { const el2 = moduleNode(f, n, m, online); if (el2) a.appendChild(el2); }
    if (foots.length) {
      const foot = el("div", "nc-foot");
      for (const f of foots) { const el2 = moduleNode(f, n, m, online); if (el2) foot.appendChild(el2); }
      a.appendChild(foot);
    }
  } else {
    const hint = el("div", "subtle", n.registered ? "等待首次上报…" : "尚未安装 agent");
    hint.style.padding = "14px 0";
    a.appendChild(hint);
  }
  return a;
}

function statusRank(n) {
  if (n.alerting) return 0;
  if (n.registered && !isOnline(n)) return 1;
  if (!n.registered) return 2;
  return 3;
}
function filteredSorted() {
  const q = $("#search").value.trim().toLowerCase();
  const grp = $("#groupFilter").value;
  const sort = $("#sortBy").value;
  let list = Array.from(NODES.values());
  if (grp) list = list.filter((n) => (n.grp || "") === grp);
  if (q) list = list.filter((n) => [n.name, n.hostname, n.os, n.grp].some((s) => (s || "").toLowerCase().includes(q)));
  list.sort((a, b) => {
    if (sort === "name") return a.name.localeCompare(b.name);
    if (sort === "cpu") return ((b.latest && b.latest.cpu_pct) || 0) - ((a.latest && a.latest.cpu_pct) || 0);
    if (sort === "mem") return pct((b.latest || {}).mem_used, (b.latest || {}).mem_total) - pct((a.latest || {}).mem_used, (a.latest || {}).mem_total);
    const r = statusRank(a) - statusRank(b);
    return r !== 0 ? r : a.name.localeCompare(b.name);
  });
  return list;
}
function renderSummary() {
  const all = Array.from(NODES.values());
  const online = all.filter((n) => n.registered && isOnline(n)).length;
  const alerting = all.filter((n) => n.alerting).length;
  const offline = all.filter((n) => n.registered && !isOnline(n)).length;
  const drift = all.filter((n) => n.registered && n.agent_version && EXPECTED_AGENT && n.agent_version !== EXPECTED_AGENT).length;
  const box = $("#summary");
  box.replaceChildren();
  const card = (label, val, cls) => {
    const c = el("div", "sum" + (cls ? " " + cls : ""));
    c.appendChild(el("div", "sum-val", String(val)));
    c.appendChild(el("div", "sum-label", label));
    return c;
  };
  box.appendChild(card("节点总数", all.length));
  box.appendChild(card("在线", online, "ok"));
  box.appendChild(card("离线", offline, offline ? "bad" : ""));
  box.appendChild(card("告警中", alerting, alerting ? "bad" : ""));
  if (drift) box.appendChild(card("待升级", drift, "warn"));
}
function renderGroupFilter() {
  const groups = Array.from(new Set(Array.from(NODES.values()).map((n) => n.grp).filter(Boolean))).sort();
  const sel = $("#groupFilter");
  const cur = sel.value;
  while (sel.options.length > 1) sel.remove(1);
  for (const g of groups) { const o = document.createElement("option"); o.value = g; o.textContent = g; sel.appendChild(o); }
  sel.value = cur;
}
function renderAll() {
  renderSummary();
  const grid = $("#grid");
  grid.replaceChildren();
  const list = filteredSorted();
  $("#empty").classList.toggle("hidden", NODES.size > 0);
  for (const n of list) grid.appendChild(renderCard(n));
}
function patchNode(id) {
  const n = NODES.get(id);
  const old = $("#node-" + id);
  if (n && old) old.replaceWith(renderCard(n));
}

async function load() {
  const data = await api("GET", "/api/nodes");
  INTERVAL = data.interval || 5;
  EXPECTED_AGENT = data.expected_agent || "";
  NODES = new Map(data.nodes.map((n) => [n.id, n]));
  renderGroupFilter();
  renderAll();
}
async function loadAlertBadge() {
  try { const d = await api("GET", "/api/alerts/events"); const b = $("#navBadge"); if (b) { b.textContent = String(d.firing); b.classList.toggle("hidden", !d.firing); } } catch (_) {}
}

document.addEventListener("DOMContentLoaded", async () => {
  try { await load(); } catch (e) {}
  loadAlertBadge();

  wsConnect((m) => {
    if (m.type === "metrics" && NODES.has(m.node_id)) {
      const n = NODES.get(m.node_id);
      n.latest = m.latest; n.last_seen = m.ts;
      renderSummary(); patchNode(m.node_id);
    } else if (m.type === "alert") {
      loadAlertBadge(); load().catch(() => {});
    }
  });
  setInterval(renderAll, 5000);

  $("#search").addEventListener("input", renderAll);
  $("#groupFilter").addEventListener("change", renderAll);
  $("#sortBy").addEventListener("change", renderAll);

  // 卡片自定义
  $("#customBtn").addEventListener("click", () => {
    const list = $("#fieldList");
    list.replaceChildren();
    for (const mod of CARD_MODULES) {
      const lab = el("label", "chk");
      const cb = el("input"); cb.type = "checkbox"; cb.value = mod.id; cb.checked = FIELDS.includes(mod.id);
      lab.appendChild(cb); lab.appendChild(el("span", null, " " + mod.name));
      list.appendChild(lab);
    }
    $("#customDlg").showModal();
  });
  $("#customForm").addEventListener("submit", (e) => {
    if (e.submitter && e.submitter.value !== "ok") return;
    const chosen = $$("#fieldList input:checked").map((c) => c.value);
    FIELDS = chosen.length ? chosen : DEFAULT_FIELDS.slice();
    localStorage.setItem("op-card-fields", JSON.stringify(FIELDS));
    renderAll();
  });
  $("#customReset").addEventListener("click", () => {
    localStorage.removeItem("op-card-fields"); FIELDS = DEFAULT_FIELDS.slice();
    $$("#fieldList input").forEach((c) => { c.checked = DEFAULT_FIELDS.includes(c.value); });
  });
});
