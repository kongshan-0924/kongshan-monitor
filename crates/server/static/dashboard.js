/* 总览(只读):状态卡片 + 汇总 + 搜索/过滤/排序 + 告警高亮 + 卡片自定义 + 版本漂移。
   管理操作(增删改/批量)已移至「服务器」模块。所有动态数据经 textContent 渲染。 */
"use strict";

let NODES = new Map();
let INTERVAL = 5;
let EXPECTED_AGENT = "";
let VIEW = localStorage.getItem("op-view") === "list" ? "list" : "grid";

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
    case "net": {
      const box = el("div", "nc-duplex");
      box.appendChild(el("span", null, "↓ " + fmtBps(m.net_rx_bps)));
      box.appendChild(el("span", null, "↑ " + fmtBps(m.net_tx_bps)));
      return box;
    }
    case "io": {
      const box = el("div", "nc-duplex");
      box.appendChild(el("span", null, "读 " + fmtBps(m.disk_read_bps)));
      box.appendChild(el("span", null, "写 " + fmtBps(m.disk_write_bps)));
      return box;
    }
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
  const nameEl = el("span", "nc-name", n.name);
  nameEl.title = n.name;
  head.appendChild(nameEl);
  if (n.alerting) head.appendChild(el("span", "nc-alert", "告警"));
  if (n.grp) head.appendChild(el("span", "nc-grp", n.grp));
  a.appendChild(head);

  const osText = (n.os || "待接入") + (n.arch ? " · " + n.arch : "");
  const osLine = el("div", "nc-os", osText);
  osLine.title = osText;
  a.appendChild(osLine);

  if (n.registered && n.agent_version && EXPECTED_AGENT && n.agent_version !== EXPECTED_AGENT) {
    const driftText = "agent " + n.agent_version + " → 可升级至 " + EXPECTED_AGENT;
    const driftLine = el("div", "nc-drift", driftText);
    driftLine.title = driftText;
    a.appendChild(driftLine);
  }

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
    if (sort === "custom") return (a.sort_order || 0) - (b.sort_order || 0);
    if (sort === "name") return a.name.localeCompare(b.name);
    if (sort === "cpu") return ((b.latest && b.latest.cpu_pct) || 0) - ((a.latest && a.latest.cpu_pct) || 0);
    if (sort === "mem") return pct((b.latest || {}).mem_used, (b.latest || {}).mem_total) - pct((a.latest || {}).mem_used, (a.latest || {}).mem_total);
    const r = statusRank(a) - statusRank(b);
    // 同一状态分组内,按服务器管理页拖拽设定的顺序排列(而非字母序),
    // 这样"按状态"默认视图也能感知到拖拽调整过的顺序。
    return r !== 0 ? r : (a.sort_order || 0) - (b.sort_order || 0);
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
  grid.classList.toggle("list-view", VIEW === "list");
  grid.replaceChildren();
  const list = filteredSorted();
  $("#empty").classList.toggle("hidden", NODES.size > 0);
  for (const n of list) grid.appendChild(renderCard(n));
}
function setView(v) {
  VIEW = v === "list" ? "list" : "grid";
  localStorage.setItem("op-view", VIEW);
  $$("#viewToggle button").forEach((b) => b.classList.toggle("active", b.dataset.view === VIEW));
  renderAll();
}
function patchNode(id) {
  const n = NODES.get(id);
  const old = $("#node-" + id);
  if (n && old) old.replaceWith(renderCard(n));
}

/* 全局趋势可选模块。cols = /api/overview/trend 点位里取用的下标(见接口注释:
   0=t 1=cpu 2=mem_used 3=mem_total 4=rx 5=tx 6=dr 7=dw 8=load1 9=disk_used 10=disk_total 11=swap_used)。 */
const TREND_MODULES = [
  { id: "cpu",  name: "平均 CPU",  title: "平均 CPU 使用率",         cols: [1],     opts: { series: [{ label: "平均 CPU %", colorVar: "--chart1", fill: true }], yFmt: (v) => v.toFixed(0) + "%", yMax: 100 } },
  { id: "mem",  name: "内存",      title: "内存合计(已用 / 总量)",  cols: [2, 3],  opts: { series: [{ label: "已用", colorVar: "--chart2", fill: true }, { label: "总量", colorVar: "--chart3" }], yFmt: fmtBytes } },
  { id: "net",  name: "网络吞吐",  title: "网络吞吐合计(下 / 上)",  cols: [4, 5],  opts: { series: [{ label: "下行", colorVar: "--chart1", fill: true }, { label: "上行", colorVar: "--chart3" }], yFmt: fmtBps } },
  { id: "io",   name: "磁盘 I/O",  title: "磁盘 I/O 合计(读 / 写)", cols: [6, 7],  opts: { series: [{ label: "读", colorVar: "--chart2", fill: true }, { label: "写", colorVar: "--chart4" }], yFmt: fmtBps } },
  { id: "load", name: "平均负载",  title: "平均负载(load1)",        cols: [8],     opts: { series: [{ label: "平均 load1", colorVar: "--chart1", fill: true }], yFmt: (v) => v.toFixed(2) } },
  { id: "disk", name: "磁盘使用",  title: "磁盘合计(已用 / 总量)",  cols: [9, 10], opts: { series: [{ label: "已用", colorVar: "--chart2", fill: true }, { label: "总量", colorVar: "--chart3" }], yFmt: fmtBytes } },
  { id: "swap", name: "Swap",      title: "Swap 合计(已用)",        cols: [11],    opts: { series: [{ label: "Swap 已用", colorVar: "--chart4", fill: true }], yFmt: fmtBytes } },
];
const TREND_DEFAULT = ["cpu", "mem"]; // 默认与改版前一致,老用户不受影响
function trendMods() {
  try { const v = JSON.parse(localStorage.getItem("op-trend-mods") || "null"); if (Array.isArray(v) && v.length) return v; } catch (_) {}
  return TREND_DEFAULT.slice();
}
let TREND = {};      // 已建图表:模块 id -> controller
let TREND_KEY = "";  // 当前已渲染的模块组合,变化时才重建 DOM/图表

function rebuildTrendGrid(modIds) {
  const grid = $("#trendGrid");
  if (!grid) return;
  Object.values(TREND).forEach((c) => c && c.destroy && c.destroy()); // 释放旧图表
  TREND = {};
  grid.replaceChildren();
  for (const id of modIds) {
    const mod = TREND_MODULES.find((m) => m.id === id);
    if (!mod) continue;
    const cardEl = el("div", "chart-card");
    cardEl.appendChild(el("h4", null, mod.title));
    const chartEl = el("div", "chart");
    cardEl.appendChild(chartEl);
    grid.appendChild(cardEl);
    TREND[id] = opChart(chartEl, mod.opts);
  }
  TREND_KEY = modIds.join(",");
}

async function loadTrend() {
  const card = $("#trendCard");
  if (!card) return;
  card.classList.toggle("hidden", NODES.size === 0);
  if (NODES.size === 0) return;
  const mods = trendMods();
  if (mods.join(",") !== TREND_KEY) rebuildTrendGrid(mods);
  const secs = parseInt($("#trendRange").value, 10) || 86400;
  let d;
  try { d = await api("GET", "/api/overview/trend?secs=" + secs); } catch (_) { return; }
  const ts = d.points.map((p) => p[0]);
  const step = d.step || 0;
  for (const id of mods) {
    const mod = TREND_MODULES.find((m) => m.id === id);
    const chart = TREND[id];
    if (!mod || !chart) continue;
    chart.setData(ts, mod.cols.map((c) => d.points.map((p) => p[c])), null, step);
  }
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
  loadTrend();
  setInterval(loadTrend, 60000);

  wsConnect((m) => {
    if (m.type === "metrics" && NODES.has(m.node_id)) {
      const n = NODES.get(m.node_id);
      n.latest = m.latest; n.last_seen = m.ts;
      renderSummary(); patchNode(m.node_id);
    } else if (m.type === "alert") {
      loadAlertBadge(); load().catch(() => {});
      if (m.firing) notifyDesktop(m.text);
    }
  }, () => { load().catch(() => {}); }); // 断线重连后重拉快照,避免实时值冻结成旧值
  setInterval(renderAll, 5000);
  // 兜底:即便 WS 长时间抽风,也每 45 秒拉一次快照自愈,不让首页实时值长期停留在旧值
  setInterval(() => { load().catch(() => {}); }, 45000);

  $("#search").addEventListener("input", renderAll);
  $("#groupFilter").addEventListener("change", renderAll);
  $("#sortBy").addEventListener("change", renderAll);
  $("#trendRange").addEventListener("change", loadTrend);

  // 卡片网格 / 紧凑列表 视图切换
  $$("#viewToggle button").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === VIEW);
    b.addEventListener("click", () => setView(b.dataset.view));
  });

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

  // 全局趋势自定义:勾选要显示哪些趋势图
  const tcb = $("#trendCustomBtn");
  if (tcb) tcb.addEventListener("click", () => {
    const list = $("#trendList"); list.replaceChildren();
    const cur = trendMods();
    for (const mod of TREND_MODULES) {
      const lab = el("label", "chk");
      const cb = el("input"); cb.type = "checkbox"; cb.value = mod.id; cb.checked = cur.includes(mod.id);
      lab.appendChild(cb); lab.appendChild(el("span", null, " " + mod.name));
      list.appendChild(lab);
    }
    $("#trendDlg").showModal();
  });
  const tform = $("#trendForm");
  if (tform) tform.addEventListener("submit", (e) => {
    if (e.submitter && e.submitter.value !== "ok") return;
    const chosen = $$("#trendList input:checked").map((c) => c.value); // DOM 序 = 模块定义序
    const mods = chosen.length ? chosen : TREND_DEFAULT.slice();
    localStorage.setItem("op-trend-mods", JSON.stringify(mods));
    loadTrend();
  });
  const treset = $("#trendReset");
  if (treset) treset.addEventListener("click", () => {
    localStorage.removeItem("op-trend-mods");
    $$("#trendList input").forEach((c) => { c.checked = TREND_DEFAULT.includes(c.value); });
  });
});
