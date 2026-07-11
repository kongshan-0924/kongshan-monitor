/* 服务器管理:增删改 + 批量,全部集中于此。 */
"use strict";

let NODES = [];
const SELECTED = new Set();
let INTERVAL = 5;
let dragSortOn = localStorage.getItem("op-srv-dragsort") === "1";
let dragFromId = null;

/* ---- 分组下拉(仅"新增分组"时才输入文本) ---- */
function knownGroups() {
  return Array.from(new Set(NODES.map((n) => n.grp).filter(Boolean))).sort();
}
function populateGroupSelect(sel, current) {
  sel.replaceChildren();
  sel.appendChild(new Option("(无分组)", ""));
  for (const g of knownGroups()) sel.appendChild(new Option(g, g));
  sel.appendChild(new Option("+ 新增分组…", "__new__"));
  sel.value = current && knownGroups().includes(current) ? current : (current ? "__new__" : "");
}
function wireGroupSelect(selEl, newRowEl, newInputEl, current) {
  populateGroupSelect(selEl, current);
  newRowEl.classList.toggle("hidden", selEl.value !== "__new__");
  if (selEl.value === "__new__") newInputEl.value = current || "";
  selEl.onchange = () => {
    newRowEl.classList.toggle("hidden", selEl.value !== "__new__");
    if (selEl.value === "__new__") { newInputEl.value = ""; newInputEl.focus(); }
  };
}
function groupSelectValue(selEl, newInputEl) {
  return selEl.value === "__new__" ? newInputEl.value.trim() : selEl.value;
}

function isOnline(n) {
  return n.last_seen && (Date.now() / 1000 - n.last_seen <= Math.max(INTERVAL * 3, 10));
}
function statusPill(n) {
  const online = isOnline(n);
  const cls = n.registered ? (online ? "on" : "off") : "pending";
  const txt = n.registered ? (online ? "在线" : "离线") : "待注册";
  const p = el("span", "spill spill-" + cls);
  p.appendChild(el("span", "spill-dot"));
  p.appendChild(el("span", null, txt));
  return p;
}

/* 流量单元格:未启用清零显示"总计",启用后显示"本期(周期起)" */
function fmtTrafficCell(n) {
  const total = (n.traffic_rx_total || 0) + (n.traffic_tx_total || 0);
  const sum = fmtBytes(total) + "(↓" + fmtBytes(n.traffic_rx_total || 0) + " ↑" + fmtBytes(n.traffic_tx_total || 0) + ")";
  if (!n.traffic_reset_enabled) return sum;
  return sum + " · 每月 " + n.traffic_reset_day + " 日清零";
}

/* ---- 列(名称固定始终显示;其余均可通过「自定义列」勾选) ---- */
function statusRank(n) {
  if (!n.registered) return 0; // 待注册
  return isOnline(n) ? 2 : 1; // 离线=1,在线=2(降序时在线排前面)
}
const COLUMN_CATALOG = [
  { key: "status", label: "状态", sort: statusRank,
    render: (n) => { const td = el("td", "nowrap"); td.appendChild(statusPill(n)); return td; } },
  { key: "grp", label: "分组", sort: (n) => (n.grp || "").toLowerCase(),
    render: (n) => { const td = el("td", "nowrap", n.grp || "—"); if (n.grp) td.title = n.grp; return td; } },
  { key: "note", label: "备注", sort: (n) => (n.note || "").toLowerCase(),
    render: (n) => { const td = el("td", "subtle nowrap nowrap-tight", n.note || "—"); if (n.note) td.title = n.note; return td; } },
  { key: "host", label: "主机/系统", sort: (n) => (n.hostname || "").toLowerCase(),
    render: (n) => { const t = (n.hostname || "—") + (n.os ? " · " + n.os : ""); const td = el("td", "subtle nowrap", t); td.title = t; return td; } },
  { key: "ip", label: "IP", sort: (n) => n.last_ip || "",
    render: (n) => { const td = el("td", "subtle nowrap", n.last_ip || "—"); if (n.last_ip) td.title = n.last_ip; return td; } },
  { key: "kernel", label: "内核", sort: (n) => (n.kernel || "").toLowerCase(),
    render: (n) => { const td = el("td", "subtle nowrap", n.kernel || "—"); if (n.kernel) td.title = n.kernel; return td; } },
  { key: "arch", label: "架构", sort: (n) => (n.arch || "").toLowerCase(),
    render: (n) => el("td", "subtle nowrap", n.arch ? n.arch + " · " + n.cores + " 核" : "—") },
  { key: "mem", label: "内存", sort: (n) => n.mem_total || 0,
    render: (n) => el("td", "subtle nowrap", n.mem_total ? fmtBytes(n.mem_total) : "—") },
  { key: "cpu_now", label: "CPU", sort: (n) => (n.latest ? n.latest.cpu_pct : -1),
    render: (n) => el("td", "subtle nowrap", n.latest ? n.latest.cpu_pct.toFixed(0) + "%" : "—") },
  { key: "load", label: "负载", sort: (n) => (n.latest ? n.latest.load1 : -1),
    render: (n) => el("td", "subtle nowrap", n.latest ? n.latest.load1.toFixed(2) : "—") },
  { key: "uptime", label: "运行时长", sort: (n) => (n.latest ? n.latest.uptime_secs : -1),
    render: (n) => el("td", "subtle nowrap", n.latest ? fmtDur(n.latest.uptime_secs) : "—") },
  { key: "agent", label: "Agent", sort: (n) => n.agent_version || "",
    render: (n) => el("td", "subtle nowrap", n.agent_version || "—") },
  { key: "traffic", label: "流量(本期)", sort: (n) => (n.traffic_rx_total || 0) + (n.traffic_tx_total || 0),
    render: (n) => { const t = fmtTrafficCell(n); const td = el("td", "subtle nowrap", t); td.title = t; return td; } },
  { key: "registered_at", label: "接入时间", sort: (n) => n.registered_at || 0,
    render: (n) => el("td", "subtle nowrap", n.registered_at ? fmtTime(n.registered_at) : "—") },
  { key: "last_seen", label: "最后上报", sort: (n) => n.last_seen || 0,
    render: (n) => el("td", "subtle nowrap", n.last_seen ? timeAgo(n.last_seen) : "从未") },
];
const DEFAULT_COLS = ["status", "grp", "note", "host", "agent", "traffic", "last_seen"];
function srvCols() {
  try {
    const v = JSON.parse(localStorage.getItem("op-srv-cols") || "null");
    if (Array.isArray(v) && v.length) {
      const filtered = v.filter((k) => COLUMN_CATALOG.some((c) => c.key === k));
      if (filtered.length) return filtered;
    }
  } catch (_) {}
  return DEFAULT_COLS.slice();
}
let COLS = srvCols();

/* ---- 排序(名称始终可排;其余取决于当前显示的列) ---- */
function sortGetter(key) {
  if (key === "name") return (n) => (n.name || "").toLowerCase();
  const col = COLUMN_CATALOG.find((c) => c.key === key);
  return col ? col.sort : (n) => (n.name || "").toLowerCase();
}
let sortKey = localStorage.getItem("op-srv-sort-key") || "name";
let sortDir = parseInt(localStorage.getItem("op-srv-sort-dir") || "1", 10) || 1;
function setSort(key) {
  if (sortKey === key) sortDir *= -1; else { sortKey = key; sortDir = 1; }
  localStorage.setItem("op-srv-sort-key", sortKey);
  localStorage.setItem("op-srv-sort-dir", String(sortDir));
  render();
}
/* 可排序表头:除鼠标点击外,支持键盘(Tab 聚焦 + Enter/Space 触发),并暴露 aria-sort
   供读屏软件播报当前排序方向(a11y)。 */
function sortableTh(key, label) {
  const active = sortKey === key;
  const arrow = active ? (sortDir === 1 ? " ▲" : " ▼") : "";
  const th = el("th", "th-sort", label + arrow);
  th.tabIndex = 0;
  th.setAttribute("role", "button");
  th.setAttribute("aria-sort", active ? (sortDir === 1 ? "ascending" : "descending") : "none");
  th.setAttribute("aria-label", "按" + label + "排序");
  const act = () => setSort(key);
  th.addEventListener("click", act);
  th.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); act(); }
  });
  return th;
}
function sortNodes(list) {
  // 排序列被隐藏后不再有意义,自动回退到按名称排序
  const key = (sortKey === "name" || COLS.includes(sortKey)) ? sortKey : "name";
  const get = sortGetter(key);
  list.sort((a, b) => {
    const av = get(a), bv = get(b);
    if (av < bv) return -1 * sortDir;
    if (av > bv) return sortDir;
    return 0;
  });
  return list;
}

function render() {
  const admin = !isViewer();
  const q = $("#search").value.trim().toLowerCase();
  let list = NODES.slice();
  if (dragSortOn) {
    list.sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));
  } else {
    if (q) list = list.filter((n) => [n.name, n.hostname, n.grp, n.os, n.last_ip].some((s) => (s || "").toLowerCase().includes(q)));
    sortNodes(list);
  }

  const activeCols = COLUMN_CATALOG.filter((c) => COLS.includes(c.key));

  const tbl = $("#srvTbl");
  tbl.replaceChildren();
  const head = el("tr");
  if (admin && dragSortOn) head.appendChild(el("th"));
  if (admin) {
    const allCb = el("input"); allCb.type = "checkbox";
    allCb.checked = list.length > 0 && list.every((n) => SELECTED.has(n.id));
    allCb.addEventListener("change", () => {
      if (allCb.checked) list.forEach((n) => SELECTED.add(n.id)); else SELECTED.clear();
      render();
    });
    const th0 = el("th"); th0.appendChild(allCb); head.appendChild(th0);
  }
  // 名称列固定始终显示
  if (dragSortOn) {
    head.appendChild(el("th", "nowrap", "名称"));
  } else {
    head.appendChild(sortableTh("name", "名称"));
  }
  activeCols.forEach((c) => {
    if (dragSortOn) { head.appendChild(el("th", "nowrap", c.label)); return; }
    head.appendChild(sortableTh(c.key, c.label));
  });
  if (admin) head.appendChild(el("th", null, "操作"));
  tbl.appendChild(head);

  for (const n of list) {
    const tr = el("tr");
    if (admin && dragSortOn) {
      tr.draggable = true;
      tr.dataset.id = String(n.id);
      tr.addEventListener("dragstart", (e) => { dragFromId = n.id; tr.classList.add("dragging"); e.dataTransfer.effectAllowed = "move"; });
      tr.addEventListener("dragend", () => { tr.classList.remove("dragging"); });
      tr.addEventListener("dragover", (e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; });
      tr.addEventListener("drop", (e) => {
        e.preventDefault();
        if (dragFromId === null || dragFromId === n.id) return;
        const from = list.findIndex((x) => x.id === dragFromId);
        const to = list.findIndex((x) => x.id === n.id);
        if (from < 0 || to < 0) return;
        const moved = list.splice(from, 1)[0];
        list.splice(to, 0, moved);
        list.forEach((x, i) => { x.sort_order = i; });
        render();
        saveOrder(list);
      });
      const handleTd = el("td", "drag-handle", "⠿");
      tr.appendChild(handleTd);
    }
    if (admin) {
      const cbTd = el("td");
      const cb = el("input"); cb.type = "checkbox"; cb.checked = SELECTED.has(n.id);
      cb.addEventListener("change", () => { if (cb.checked) SELECTED.add(n.id); else SELECTED.delete(n.id); updateBatch(); });
      cbTd.appendChild(cb); tr.appendChild(cbTd);
    }

    const nameTd = el("td", "nowrap"); nameTd.title = n.name;
    const link = el("a", null, n.name); link.href = "/nodes/" + n.id; link.style.fontWeight = "600";
    nameTd.appendChild(link); tr.appendChild(nameTd);
    activeCols.forEach((c) => tr.appendChild(c.render(n)));

    if (admin) {
      const ops = el("td", "ops");
      const edit = el("button", "btn ghost xs", "编辑");
      edit.addEventListener("click", () => openEdit(n));
      ops.appendChild(edit);
      if (n.registered) {
        const regen = el("button", "btn ghost xs", "重置密钥");
        regen.addEventListener("click", () => regenKey(n));
        const revoke = el("button", "btn warn xs", "吊销");
        revoke.addEventListener("click", () => revokeNode(n));
        ops.appendChild(regen); ops.appendChild(revoke);
      } else {
        const install = el("button", "btn primary xs", "一键安装");
        install.addEventListener("click", () => showInstallCmd(n));
        ops.appendChild(install);
      }
      const del = el("button", "btn danger xs", "删除");
      del.addEventListener("click", () => delNode(n));
      ops.appendChild(del);
      tr.appendChild(ops);
    }
    tbl.appendChild(tr);
  }
  if (!list.length) {
    const tr = el("tr"); const td = el("td", "subtle", NODES.length ? "无匹配" : "还没有服务器,点右上角「添加节点」");
    let span = 1 /* 名称 */ + activeCols.length;
    if (admin) span += 1 /* 勾选 */ + 1 /* 操作 */ + (dragSortOn ? 1 : 0);
    td.colSpan = span; tr.appendChild(td); tbl.appendChild(tr);
  }
  updateBatch();
}

function updateBatch() {
  $("#batchbar").classList.toggle("hidden", SELECTED.size === 0);
  $("#selCount").textContent = "已选 " + SELECTED.size;
}

let saveOrderTimer = null;
function saveOrder(list) {
  clearTimeout(saveOrderTimer);
  saveOrderTimer = setTimeout(async () => {
    try { await api("POST", "/api/nodes/reorder", { ids: list.map((n) => n.id) }); } catch (e) { alert(e.error || "排序保存失败"); }
  }, 400);
}
function setDragSort(on) {
  dragSortOn = on;
  localStorage.setItem("op-srv-dragsort", on ? "1" : "0");
  $("#dragSortBtn").textContent = "拖拽排序:" + (on ? "开" : "关");
  $("#dragSortBtn").classList.toggle("primary", on);
  $("#dragSortBtn").classList.toggle("ghost", !on);
  $("#search").disabled = on;
  render();
}

async function load() {
  const d = await api("GET", "/api/nodes");
  INTERVAL = d.interval || 5;
  NODES = d.nodes || [];
  // 清理已不存在的选中项
  const ids = new Set(NODES.map((n) => n.id));
  for (const id of Array.from(SELECTED)) if (!ids.has(id)) SELECTED.delete(id);
  render();
}

/* ---- 单节点操作 ---- */
let editingId = null;
function openEdit(n) {
  editingId = n.id;
  $("#eName").value = n.name; $("#eNote").value = n.note || "";
  wireGroupSelect($("#eGrpSel"), $("#eGrpNewRow"), $("#eGrpNew"), n.grp || "");
  $("#eTrafficReset").checked = !!n.traffic_reset_enabled;
  $("#eTrafficDay").value = n.traffic_reset_day || 1;
  $("#eTrafficDayRow").classList.toggle("hidden", !n.traffic_reset_enabled);
  $("#editMsg").textContent = "";
  $("#editDlg").showModal();
}
async function revokeNode(n) {
  if (!confirm("吊销「" + n.name + "」的 token?其 agent 将立即无法上报。")) return;
  try { await api("POST", "/api/nodes/" + n.id + "/revoke"); load(); } catch (e) { alert(e.error || "失败"); }
}
async function regenKey(n) {
  if (!confirm("重置将吊销旧 token 并生成新的一次性安装密钥,确认?")) return;
  try {
    const r = await api("POST", "/api/nodes/" + n.id + "/regen_key");
    $("#cmdDlgTitle").textContent = "新安装命令";
    $("#cmdDlgHint").textContent = "旧 token 已吊销。在目标机重新执行(30 分钟内有效):";
    $("#newCmd").textContent = r.command; $("#cmdDlg").showModal(); load();
  } catch (e) { alert(e.error || "失败"); }
}
/* 待注册节点:随时可重新取回一键安装命令(旧密钥尚未使用,直接换发新的,
   命令按当前服务端配置实时渲染,设置里改了 public_url 等也会跟着变)。 */
async function showInstallCmd(n) {
  try {
    const r = await api("POST", "/api/nodes/" + n.id + "/regen_key");
    $("#cmdDlgTitle").textContent = "一键安装命令 · " + n.name;
    $("#cmdDlgHint").textContent = "在目标服务器以 root 执行(密钥 30 分钟内有效、仅此一次显示):";
    $("#newCmd").textContent = r.command; $("#cmdDlg").showModal(); load();
  } catch (e) { alert(e.error || "失败"); }
}
async function delNode(n) {
  if (!confirm("删除「" + n.name + "」及其全部历史数据?不可恢复。")) return;
  try { await api("DELETE", "/api/nodes/" + n.id); SELECTED.delete(n.id); load(); } catch (e) { alert(e.error || "失败"); }
}

/* ---- 批量 ---- */
async function batch(action, extra) {
  const ids = Array.from(SELECTED);
  if (!ids.length) return;
  try {
    const r = await api("POST", "/api/nodes/batch", Object.assign({ action, ids }, extra || {}));
    SELECTED.clear(); await load(); alert("已处理 " + r.affected + " 个节点");
  } catch (e) { alert(e.error || "操作失败"); }
}
/* 远程升级:在线节点立即下发;触发瞬间恰在重连的节点进入 30 秒补发窗口,重连后自动补发。
   升级是否最终成功需稍后核对 Agent 版本——agent 侧下载/助手失败不会回传结果,可直接重试。 */
async function batchUpgrade() {
  const ids = Array.from(SELECTED);
  if (!ids.length) return;
  try {
    const r = await api("POST", "/api/nodes/batch", { action: "upgrade", ids });
    SELECTED.clear(); await load();
    const queued = (r.queued && r.queued.length) || (r.offline && r.offline.length) || 0;
    let msg = "已触发 " + r.affected + " 个节点升级(实际是否成功需稍后核对 Agent 版本)。";
    if (queued) msg += "\n另有 " + queued + " 个节点正在重连,已排入 30 秒补发窗口,重连后自动补发;如仍未生效可稍后重试。";
    alert(msg);
  } catch (e) { alert(e.error || "操作失败"); }
}

document.addEventListener("DOMContentLoaded", async () => {
  await myRole();
  try { await load(); } catch (e) {}
  loadAlertBadge();
  setInterval(load, 8000);

  setDragSort(dragSortOn);
  $("#dragSortBtn").addEventListener("click", () => setDragSort(!dragSortOn));
  $("#search").addEventListener("input", render);

  // 自定义列
  $("#srvColsBtn").addEventListener("click", () => {
    const list = $("#srvColList");
    list.replaceChildren();
    for (const c of COLUMN_CATALOG) {
      const lab = el("label", "chk");
      const cb = el("input"); cb.type = "checkbox"; cb.value = c.key; cb.checked = COLS.includes(c.key);
      lab.appendChild(cb); lab.appendChild(el("span", null, " " + c.label));
      list.appendChild(lab);
    }
    $("#srvColDlg").showModal();
  });
  $("#srvColForm").addEventListener("submit", (e) => {
    if (e.submitter && e.submitter.value !== "ok") return;
    const chosen = $$("#srvColList input:checked").map((c) => c.value);
    COLS = chosen.length ? chosen : DEFAULT_COLS.slice();
    localStorage.setItem("op-srv-cols", JSON.stringify(COLS));
    render();
  });
  $("#srvColReset").addEventListener("click", () => {
    localStorage.removeItem("op-srv-cols"); COLS = DEFAULT_COLS.slice();
    $$("#srvColList input").forEach((c) => { c.checked = DEFAULT_COLS.includes(c.value); });
  });
  $("#selClear").addEventListener("click", () => { SELECTED.clear(); render(); });
  $("#batchDelete").addEventListener("click", () => { if (SELECTED.size && confirm("删除选中 " + SELECTED.size + " 个节点及历史数据?不可恢复。")) batch("delete"); });
  $("#batchRevoke").addEventListener("click", () => { if (SELECTED.size && confirm("吊销选中 " + SELECTED.size + " 个节点的 token?")) batch("revoke"); });
  $("#batchSetGrp").addEventListener("click", () => batch("set_group", { grp: $("#batchGrp").value.trim() }));
  $("#batchUpgrade").addEventListener("click", () => {
    if (!SELECTED.size) return;
    if (!confirm("触发选中 " + SELECTED.size + " 个节点远程升级 agent?仅对当前在线的节点生效,离线节点需另行手动升级。")) return;
    batchUpgrade();
  });

  // 编辑保存
  $("#eTrafficReset").addEventListener("change", () => {
    $("#eTrafficDayRow").classList.toggle("hidden", !$("#eTrafficReset").checked);
  });
  $("#editForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault();
    try {
      await api("POST", "/api/nodes/" + editingId + "/rename", {
        name: $("#eName").value.trim(), grp: groupSelectValue($("#eGrpSel"), $("#eGrpNew")), note: $("#eNote").value.trim(),
        traffic_reset_enabled: $("#eTrafficReset").checked,
        traffic_reset_day: parseInt($("#eTrafficDay").value, 10) || 1,
      });
      $("#editDlg").close(); load();
    } catch (err) { $("#editMsg").textContent = err.error || "保存失败"; }
  });

  // 添加节点
  const dlg = $("#addDlg");
  $("#nodeTrafficReset").addEventListener("change", () => {
    $("#nodeTrafficDayRow").classList.toggle("hidden", !$("#nodeTrafficReset").checked);
  });
  $("#addNodeBtn").addEventListener("click", () => {
    $("#addStep1").classList.remove("hidden"); $("#addStep2").classList.add("hidden");
    $("#nodeName").value = "";
    wireGroupSelect($("#nodeGrpSel"), $("#nodeGrpNewRow"), $("#nodeGrpNew"), "");
    $("#nodeTrafficReset").checked = false; $("#nodeTrafficDay").value = 1;
    $("#nodeTrafficDayRow").classList.add("hidden");
    dlg.showModal();
  });
  $("#addForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    if (!$("#addStep2").classList.contains("hidden")) return;
    e.preventDefault();
    const btn = $("#createBtn"); btn.disabled = true;
    try {
      const r = await api("POST", "/api/nodes", {
        name: $("#nodeName").value.trim(), grp: groupSelectValue($("#nodeGrpSel"), $("#nodeGrpNew")),
        traffic_reset_enabled: $("#nodeTrafficReset").checked,
        traffic_reset_day: parseInt($("#nodeTrafficDay").value, 10) || 1,
      });
      $("#installCmd").textContent = r.command;
      $("#addStep1").classList.add("hidden"); $("#addStep2").classList.remove("hidden");
      await load();
    } catch (err) { alert(err.error || "创建失败"); } finally { btn.disabled = false; }
  });
  const copy = (sel, btn) => { navigator.clipboard.writeText($(sel).textContent).then(() => { const t = $(btn).textContent; $(btn).textContent = "已复制 ✓"; setTimeout(() => { $(btn).textContent = t; }, 1500); }).catch(() => alert("复制失败")); };
  $("#copyCmd").addEventListener("click", () => copy("#installCmd", "#copyCmd"));
  $("#copyNewCmd").addEventListener("click", () => copy("#newCmd", "#copyNewCmd"));
  $("#closeCmdDlg").addEventListener("click", () => $("#cmdDlg").close());
});

async function loadAlertBadge() {
  try { const d = await api("GET", "/api/alerts/events"); const b = $("#navBadge"); if (b) { b.textContent = String(d.firing); b.classList.toggle("hidden", !d.firing); } } catch (_) {}
}
