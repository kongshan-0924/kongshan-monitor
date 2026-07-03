/* 总览页:节点卡片网格 + 汇总栏 + 搜索/过滤/排序 + 告警高亮 + 批量选择 + 版本漂移。
   所有动态数据仅经 textContent/createElement 渲染。 */
"use strict";

let NODES = new Map();      // id -> node
let INTERVAL = 5;
let EXPECTED_AGENT = "";
let selMode = false;
const SELECTED = new Set();

function meterEl(label, used, total, fmtFn) {
  const p = pct(used, total);
  const wrap = el("div", "meter");
  const lab = el("div", "m-label");
  lab.appendChild(el("span", null, label));
  lab.appendChild(el("span", null, total ? (fmtFn ? fmtFn(used) + " / " + fmtFn(total) : p.toFixed(0) + "%") : "-"));
  const bar = el("div", "m-bar");
  const fill = el("div", "m-fill" + (p > 90 ? " bad" : p > 70 ? " warn" : ""));
  fill.style.width = p.toFixed(1) + "%";
  bar.appendChild(fill);
  wrap.appendChild(lab);
  wrap.appendChild(bar);
  return wrap;
}

function isOnline(n) {
  if (!n.last_seen) return false;
  return Date.now() / 1000 - n.last_seen <= Math.max(INTERVAL * 3, 10);
}

function renderCard(n) {
  const online = isOnline(n);
  const wrap = el("div", "card node-card" + (n.alerting ? " alerting" : ""));
  wrap.id = "node-" + n.id;

  const head = el("div", "nc-head");
  if (selMode) {
    const cb = el("input");
    cb.type = "checkbox";
    cb.className = "nc-check";
    cb.checked = SELECTED.has(n.id);
    cb.addEventListener("click", (e) => {
      e.stopPropagation();
      if (cb.checked) SELECTED.add(n.id); else SELECTED.delete(n.id);
      updateBatchBar();
    });
    head.appendChild(cb);
  }
  const dot = el("span", "dot " + (n.registered ? (online ? "on" : "off") : "pending"));
  dot.title = n.registered ? (online ? "在线" : "离线") : "待注册";
  head.appendChild(dot);
  head.appendChild(el("span", "nc-name", n.name));
  if (n.alerting) head.appendChild(el("span", "nc-alert", "告警"));
  if (n.grp) head.appendChild(el("span", "nc-grp", n.grp));
  wrap.appendChild(head);

  const osLine = el("div", "nc-os", (n.os || "待接入") + (n.arch ? " · " + n.arch : ""));
  if (n.registered && n.agent_version && EXPECTED_AGENT && n.agent_version !== EXPECTED_AGENT) {
    osLine.appendChild(el("span", "nc-drift", " agent " + n.agent_version + " ↑" + EXPECTED_AGENT));
  }
  wrap.appendChild(osLine);

  const m = n.latest;
  if (m) {
    wrap.appendChild(meterEl("CPU", m.cpu_pct, 100));
    wrap.appendChild(meterEl("内存", m.mem_used, m.mem_total, fmtBytes));
    wrap.appendChild(meterEl("磁盘", m.disk_used, m.disk_total, fmtBytes));
    const foot = el("div", "nc-foot");
    foot.appendChild(el("span", null, "↓ " + fmtBps(m.net_rx_bps) + "  ↑ " + fmtBps(m.net_tx_bps)));
    foot.appendChild(el("span", null, online ? "运行 " + fmtDur(m.uptime_secs) : timeAgo(n.last_seen)));
    wrap.appendChild(foot);
  } else {
    const hint = el("div", "subtle", n.registered ? "等待首次上报…" : "尚未安装 agent");
    hint.style.padding = "14px 0";
    wrap.appendChild(hint);
  }

  // 选择模式下点击切换选中;否则进入详情
  wrap.addEventListener("click", () => {
    if (selMode) {
      if (SELECTED.has(n.id)) SELECTED.delete(n.id); else SELECTED.add(n.id);
      renderAll();
      return;
    }
    location.href = "/nodes/" + encodeURIComponent(n.id);
  });
  wrap.style.cursor = "pointer";
  return wrap;
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
  if (q) list = list.filter((n) =>
    [n.name, n.hostname, n.os, n.grp].some((s) => (s || "").toLowerCase().includes(q)));
  list.sort((a, b) => {
    if (sort === "name") return a.name.localeCompare(b.name);
    if (sort === "cpu") return ((b.latest && b.latest.cpu_pct) || 0) - ((a.latest && a.latest.cpu_pct) || 0);
    if (sort === "mem") return pct((b.latest || {}).mem_used, (b.latest || {}).mem_total) - pct((a.latest || {}).mem_used, (a.latest || {}).mem_total);
    // status
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
  for (const sel of [$("#groupFilter"), $("#batchGrp")]) {
    const cur = sel.value;
    // 保留第一个占位 option
    while (sel.options.length > 1) sel.remove(1);
    for (const g of groups) {
      const o = document.createElement("option");
      o.value = g; o.textContent = g;
      sel.appendChild(o);
    }
    sel.value = cur;
  }
}

function renderAll() {
  renderSummary();
  const grid = $("#grid");
  grid.replaceChildren();
  const list = filteredSorted();
  $("#empty").classList.toggle("hidden", NODES.size > 0);
  for (const n of list) grid.appendChild(renderCard(n));
  updateBatchBar();
}

function updateBatchBar() {
  $("#batchbar").classList.toggle("hidden", !selMode);
  $("#selCount").textContent = "已选 " + SELECTED.size;
}

async function load() {
  const data = await api("GET", "/api/nodes");
  INTERVAL = data.interval || 5;
  EXPECTED_AGENT = data.expected_agent || "";
  NODES = new Map(data.nodes.map((n) => [n.id, n]));
  renderGroupFilter();
  renderAll();
}

async function batchAction(action, extra) {
  const ids = Array.from(SELECTED);
  if (!ids.length) return;
  try {
    const r = await api("POST", "/api/nodes/batch", Object.assign({ action, ids }, extra || {}));
    SELECTED.clear();
    await load();
    alert("已处理 " + r.affected + " 个节点");
  } catch (e) { alert(e.error || "操作失败"); }
}

document.addEventListener("DOMContentLoaded", async () => {
  try { await load(); } catch (e) { /* 401 已跳转 */ }
  loadAlertBadge();

  wsConnect((m) => {
    if (m.type === "metrics" && NODES.has(m.node_id)) {
      const n = NODES.get(m.node_id);
      n.latest = m.latest; n.last_seen = m.ts;
      renderSummary();
      const old = $("#node-" + m.node_id);
      if (old && !selMode) old.replaceWith(renderCard(n));
    } else if (m.type === "alert") {
      loadAlertBadge();
      load().catch(() => {}); // 告警状态变化 → 刷新高亮
    }
  });
  setInterval(() => { if (!selMode) renderAll(); }, 5000);

  // 工具栏
  $("#search").addEventListener("input", renderAll);
  $("#groupFilter").addEventListener("change", renderAll);
  $("#sortBy").addEventListener("change", renderAll);
  $("#selMode").addEventListener("change", (e) => {
    selMode = e.target.checked;
    if (!selMode) SELECTED.clear();
    renderAll();
  });
  $("#selClear").addEventListener("click", () => { SELECTED.clear(); renderAll(); });
  $("#batchDelete").addEventListener("click", () => {
    if (SELECTED.size && confirm("确认删除选中的 " + SELECTED.size + " 个节点及其历史数据?不可恢复。")) batchAction("delete");
  });
  $("#batchRevoke").addEventListener("click", () => {
    if (SELECTED.size && confirm("确认吊销选中的 " + SELECTED.size + " 个节点的 token?")) batchAction("revoke");
  });
  $("#batchSetGrp").addEventListener("click", () => {
    const grp = $("#batchGrp").value;
    batchAction("set_group", { grp });
  });

  // 添加节点
  const dlg = $("#addDlg");
  $("#addNodeBtn").addEventListener("click", () => {
    $("#addStep1").classList.remove("hidden");
    $("#addStep2").classList.add("hidden");
    $("#nodeName").value = ""; $("#nodeGrp").value = "";
    dlg.showModal();
  });
  $("#addForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    if (!$("#addStep2").classList.contains("hidden")) return;
    e.preventDefault();
    const btn = $("#createBtn");
    btn.disabled = true;
    try {
      const r = await api("POST", "/api/nodes", {
        name: $("#nodeName").value.trim(),
        grp: $("#nodeGrp").value.trim(),
      });
      $("#installCmd").textContent = r.command;
      $("#addStep1").classList.add("hidden");
      $("#addStep2").classList.remove("hidden");
      await load();
    } catch (err) { alert(err.error || "创建失败"); }
    finally { btn.disabled = false; }
  });
  $("#copyCmd").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("#installCmd").textContent);
      $("#copyCmd").textContent = "已复制 ✓";
      setTimeout(() => { $("#copyCmd").textContent = "复制命令"; }, 1500);
    } catch (_) { alert("复制失败,请手动选择文本"); }
  });
});

async function loadAlertBadge() {
  try {
    const d = await api("GET", "/api/alerts/events");
    const b = $("#navBadge");
    if (b) { b.textContent = String(d.firing); b.classList.toggle("hidden", !d.firing); }
  } catch (_) {}
}
