/* 节点详情页:实时曲线 + 历史图表 + 系统信息 + 管理操作。 */
"use strict";

const NODE_ID = (() => {
  const m = location.pathname.match(/^\/nodes\/(\d{1,12})$/);
  if (!m) { location.href = "/"; return 0; }
  return parseInt(m[1], 10);
})();

let charts = {};
let curSecs = 3600;
let nodeInfo = null;

/* 进程占用 Top 排序状态(默认按 CPU 降序,与原行为一致) */
let topProcSort = { key: "cpu_pct", dir: -1 };
const TOP_PROC_COLS = [
  { key: "name", label: "进程", get: (p) => (p.name || "").toLowerCase() },
  { key: "cpu_pct", label: "CPU", get: (p) => p.cpu_pct || 0 },
  { key: "rss", label: "内存(RSS)", get: (p) => p.rss || 0 },
];

function statCard(label, value, sub) {
  const c = el("div", "card stat");
  c.appendChild(el("div", "s-label", label));
  c.appendChild(el("div", "s-value", value));
  if (sub) c.appendChild(el("div", "s-sub", sub));
  return c;
}

function renderStats(n, m) {
  const row = $("#statRow");
  row.replaceChildren();
  const online = n.online;
  row.appendChild(statCard("状态", n.registered ? (online ? "在线" : "离线") : "待注册",
    n.last_seen ? "最后上报 " + timeAgo(n.last_seen) : ""));
  if (!m) return;
  row.appendChild(statCard("CPU", m.cpu_pct.toFixed(1) + "%", "负载 " + m.load1.toFixed(2)));
  row.appendChild(statCard("内存", pct(m.mem_used, m.mem_total).toFixed(0) + "%",
    fmtBytes(m.mem_used) + " / " + fmtBytes(m.mem_total)));
  row.appendChild(statCard("磁盘", pct(m.disk_used, m.disk_total).toFixed(0) + "%",
    fmtBytes(m.disk_used) + " / " + fmtBytes(m.disk_total)));
  row.appendChild(statCard("网络", "↓" + fmtBps(m.net_rx_bps), "↑" + fmtBps(m.net_tx_bps)));
  row.appendChild(statCard("运行时长", fmtDur(m.uptime_secs), "进程 " + m.procs));
  const trafficTotal = (n.traffic_rx_total || 0) + (n.traffic_tx_total || 0);
  row.appendChild(statCard(
    n.traffic_reset_enabled ? "流量(本期)" : "流量(累计)",
    fmtBytes(trafficTotal),
    "↓" + fmtBytes(n.traffic_rx_total || 0) + " ↑" + fmtBytes(n.traffic_tx_total || 0)
    + (n.traffic_reset_enabled ? " · 每月 " + n.traffic_reset_day + " 日清零" : "")
  ));
}

function renderSysInfo(n, m) {
  const dl = $("#sysInfo");
  dl.replaceChildren();
  const d = (m && m.detail) || {};
  const temp = d.cpu_temp_c != null ? d.cpu_temp_c.toFixed(1) + " ℃" : "无传感器";
  let tcp = d.tcp_conns != null ? String(d.tcp_conns) : "-";
  if (d.tcp_estab != null) {
    tcp += "(活动 " + d.tcp_estab + " / 监听 " + d.tcp_listen + " / 等待 " + d.tcp_time_wait + ")";
  }
  const iops = (d.disk_read_iops != null)
    ? "读 " + d.disk_read_iops + " / 写 " + d.disk_write_iops : "-";
  const rows = [
    ["主机名", n.hostname || "-"],
    ["系统", n.os || "-"],
    ["内核", n.kernel || "-"],
    ["架构", (n.arch || "-") + " · " + n.cores + " 核"],
    ["内存", fmtBytes(n.mem_total)],
    ["Agent", n.agent_version || "-"],
    ["接入时间", fmtTime(n.registered_at)],
    ["Swap", m ? fmtBytes(m.swap_used) + " / " + fmtBytes(m.swap_total) : "-"],
    ["CPU 温度", temp],
    ["TCP 连接", tcp],
    ["磁盘 IOPS", iops],
    ["本期流量统计起", n.traffic_reset_enabled && n.traffic_period_start ? fmtTime(n.traffic_period_start) : "未启用清零(累计不清零)"],
  ];
  for (const [k, v] of rows) {
    dl.appendChild(el("dt", null, k));
    dl.appendChild(el("dd", null, v));
  }
}

function renderTables(detail) {
  const dt = $("#diskTbl");
  dt.replaceChildren();
  const dh = el("tr");
  ["挂载点", "文件系统", "用量", "使用率", "inode"].forEach((h) => dh.appendChild(el("th", null, h)));
  dt.appendChild(dh);
  for (const d of (detail && detail.disks) || []) {
    const tr = el("tr");
    const mountTd = el("td", "nowrap", d.mount); mountTd.title = d.mount; tr.appendChild(mountTd);
    tr.appendChild(el("td", null, d.fs));
    tr.appendChild(el("td", null, fmtBytes(d.used) + " / " + fmtBytes(d.total)));
    tr.appendChild(el("td", null, pct(d.used, d.total).toFixed(0) + "%"));
    const it = d.inodes_total || 0;
    tr.appendChild(el("td", null, it > 0 ? (pct(d.inodes_used || 0, it).toFixed(0) + "%") : "—"));
    dt.appendChild(tr);
  }
  const nt = $("#netTbl");
  nt.replaceChildren();
  const nh = el("tr");
  ["网卡", "下行", "上行", "累计收 / 发"].forEach((h) => nh.appendChild(el("th", null, h)));
  nt.appendChild(nh);
  for (const x of (detail && detail.nets) || []) {
    const tr = el("tr");
    const nicTd = el("td", "nowrap", x.name); nicTd.title = x.name; tr.appendChild(nicTd);
    tr.appendChild(el("td", null, fmtBps(x.rx_bps)));
    tr.appendChild(el("td", null, fmtBps(x.tx_bps)));
    tr.appendChild(el("td", null, fmtBytes(x.rx_bytes) + " / " + fmtBytes(x.tx_bytes)));
    nt.appendChild(tr);
  }

  // 每核 CPU(有数据才显示)
  const ccard = $("#coreCard");
  const cores = (detail && detail.cpu_per_core) || [];
  if (ccard) {
    ccard.classList.toggle("hidden", cores.length === 0);
    const cb = $("#coreBars");
    cb.replaceChildren();
    cores.forEach((v, i) => {
      const val = Math.max(0, Math.min(100, v || 0));
      const item = el("div", "core-item");
      item.appendChild(el("span", "core-lbl", "#" + i));
      const track = el("div", "core-track");
      const fill = el("div", "core-fill");
      fill.style.width = val.toFixed(0) + "%";
      if (val >= 90) fill.classList.add("hot");
      else if (val >= 70) fill.classList.add("warm");
      track.appendChild(fill);
      item.appendChild(track);
      item.appendChild(el("span", "core-val", val.toFixed(0) + "%"));
      cb.appendChild(item);
    });
  }

  // 进程占用 Top(可按列点击排序,升/降序切换)
  const tpcard = $("#topProcCard");
  const tops = ((detail && detail.top_procs) || []).slice();
  if (tpcard) {
    tpcard.classList.toggle("hidden", tops.length === 0);
    const col = TOP_PROC_COLS.find((c) => c.key === topProcSort.key) || TOP_PROC_COLS[1];
    tops.sort((a, b) => {
      const av = col.get(a), bv = col.get(b);
      if (av < bv) return -1 * topProcSort.dir;
      if (av > bv) return topProcSort.dir;
      return 0;
    });
    const tt = $("#topProcTbl");
    tt.replaceChildren();
    const tth = el("tr");
    TOP_PROC_COLS.forEach((c) => {
      const arrow = topProcSort.key === c.key ? (topProcSort.dir === 1 ? " ▲" : " ▼") : "";
      const th = el("th", "th-sort", c.label + arrow);
      th.addEventListener("click", () => {
        if (topProcSort.key === c.key) topProcSort.dir *= -1;
        else topProcSort = { key: c.key, dir: c.key === "name" ? 1 : -1 };
        renderTables(detail);
      });
      tth.appendChild(th);
    });
    tt.appendChild(tth);
    for (const p of tops) {
      const tr = el("tr");
      const procNameTd = el("td", "nowrap", p.name); procNameTd.title = p.name; tr.appendChild(procNameTd);
      tr.appendChild(el("td", "nowrap", (p.cpu_pct || 0).toFixed(1) + "%"));
      tr.appendChild(el("td", "nowrap", fmtBytes(p.rss || 0)));
      tt.appendChild(tr);
    }
  }

  // 服务状态(仅在 agent 配置了 watch_services 时有数据)
  const scard = $("#svcCard");
  const svcs = (detail && detail.services) || [];
  if (scard) {
    scard.classList.toggle("hidden", svcs.length === 0);
    const st = $("#svcTbl");
    st.replaceChildren();
    const sh = el("tr");
    ["服务单元", "状态"].forEach((h) => sh.appendChild(el("th", null, h)));
    st.appendChild(sh);
    for (const s of svcs) {
      const tr = el("tr");
      const svcNameTd = el("td", "nowrap", s.name); svcNameTd.title = s.name; tr.appendChild(svcNameTd);
      const td = el("td");
      td.appendChild(el("span", "spill " + (s.active ? "spill-on" : "spill-off"), s.active ? "运行中" : "未运行"));
      tr.appendChild(td);
      st.appendChild(tr);
    }
  }

  // Docker 容器(仅在 agent 开启 docker_stats 时有数据)
  const dcard = $("#dockerCard");
  const containers = (detail && detail.containers) || [];
  if (dcard) {
    dcard.classList.toggle("hidden", containers.length === 0);
    const dt = $("#dockerTbl");
    dt.replaceChildren();
    const dh = el("tr");
    ["容器", "状态", "CPU", "内存"].forEach((h) => dh.appendChild(el("th", null, h)));
    dt.appendChild(dh);
    for (const c of containers) {
      const tr = el("tr");
      const cNameTd = el("td", "nowrap", c.name); cNameTd.title = c.name; tr.appendChild(cNameTd);
      const td = el("td");
      const running = c.state === "running";
      td.appendChild(el("span", "spill " + (running ? "spill-on" : "spill-off"), c.state));
      tr.appendChild(td);
      tr.appendChild(el("td", "nowrap", (c.cpu_pct || 0).toFixed(1) + "%"));
      tr.appendChild(el("td", "nowrap", c.mem_limit ? (fmtBytes(c.mem_used || 0) + " / " + fmtBytes(c.mem_limit)) : fmtBytes(c.mem_used || 0)));
      dt.appendChild(tr);
    }
  }

  // 受监控进程(仅在 agent 配置了 watch_processes 时有数据)
  const pcard = $("#procCard");
  const watch = (detail && detail.procs_watch) || [];
  if (pcard) {
    pcard.classList.toggle("hidden", watch.length === 0);
    const pt = $("#procTbl");
    pt.replaceChildren();
    const ph = el("tr");
    ["进程", "状态", "实例数", "CPU", "内存(RSS)"].forEach((h) => ph.appendChild(el("th", null, h)));
    pt.appendChild(ph);
    for (const p of watch) {
      const tr = el("tr");
      const watchNameTd = el("td", "nowrap", p.name); watchNameTd.title = p.name; tr.appendChild(watchNameTd);
      const stTd = el("td");
      stTd.appendChild(el("span", "pill " + (p.running ? "on" : "off"), p.running ? "运行中" : "未运行"));
      tr.appendChild(stTd);
      tr.appendChild(el("td", "nowrap", String(p.count)));
      tr.appendChild(el("td", "nowrap", (p.cpu_pct || 0).toFixed(1) + "%"));
      tr.appendChild(el("td", "nowrap", fmtBytes(p.rss)));
      pt.appendChild(tr);
    }
  }
}

function buildCharts() {
  charts.cpu = opChart($("#cpuChart"), {
    series: [{ label: "CPU %", colorVar: "--chart1", fill: true }],
    yFmt: (v) => v.toFixed(0) + "%", yMax: 100,
  });
  charts.mem = opChart($("#memChart"), {
    series: [{ label: "已用内存", colorVar: "--chart2", fill: true }],
    yFmt: fmtBytes,
  });
  charts.net = opChart($("#netChart"), {
    series: [
      { label: "下行", colorVar: "--chart1", fill: true },
      { label: "上行", colorVar: "--chart3" },
    ],
    yFmt: fmtBps,
  });
  charts.io = opChart($("#ioChart"), {
    series: [
      { label: "读", colorVar: "--chart2", fill: true },
      { label: "写", colorVar: "--chart4" },
    ],
    yFmt: fmtBps,
  });
  charts.load = opChart($("#loadChart"), {
    series: [{ label: "load1", colorVar: "--chart1" }],
    yFmt: (v) => v.toFixed(2),
  });
}

async function loadHistory() {
  const h = await api("GET", "/api/nodes/" + NODE_ID + "/metrics?secs=" + curSecs);
  const ts = [], cpu = [], mem = [], rx = [], tx = [], dr = [], dw = [], l1 = [];
  // 下标 9..14:每桶峰值(旧服务端没有则为 undefined → 归一成 null,不画带)
  const cM = [], rxM = [], txM = [], drM = [], dwM = [], l1M = [];
  const nn = (v) => (v == null ? null : v);
  for (const p of h.points) {
    ts.push(p[0]); cpu.push(p[1]); mem.push(p[2]);
    rx.push(p[4]); tx.push(p[5]); dr.push(p[6]); dw.push(p[7]); l1.push(p[8]);
    cM.push(nn(p[9])); rxM.push(nn(p[10])); txM.push(nn(p[11]));
    drM.push(nn(p[12])); dwM.push(nn(p[13])); l1M.push(nn(p[14]));
  }
  const step = h.step || 0; // 供空档断线/底纹判定
  charts.cpu.setData(ts, [cpu], [cM], step);
  charts.mem.setData(ts, [mem], null, step);
  charts.net.setData(ts, [rx, tx], [rxM, txM], step);
  charts.io.setData(ts, [dr, dw], [drM, dwM], step);
  charts.load.setData(ts, [l1], [l1M], step);
}

async function loadDetail() {
  const d = await api("GET", "/api/nodes/" + NODE_ID);
  nodeInfo = d.node;
  $("#nodeTitle").textContent = d.node.name;
  $("#nodeTitle").title = d.node.name;
  const subText = (d.node.grp ? "[" + d.node.grp + "] " : "") +
    (d.node.hostname || "") + (d.node.note ? " · " + d.node.note : "") +
    (d.node.revoked && !d.node.registered ? " · token 已吊销" : "");
  $("#nodeSub").textContent = subText;
  $("#nodeSub").title = subText;
  document.title = "空山Outpost · " + d.node.name;
  renderStats(d.node, d.latest);
  renderSysInfo(d.node, d.latest);
  renderTables(d.latest && d.latest.detail);
}

document.addEventListener("DOMContentLoaded", async () => {
  buildCharts();
  // 深链接:从 URL ?secs= 恢复时间范围(仅接受按钮上的合法值)
  const wanted = new URLSearchParams(location.search).get("secs");
  const validSecs = $$("#rangeSeg button").map((b) => b.dataset.secs);
  if (wanted && validSecs.includes(wanted)) {
    curSecs = parseInt(wanted, 10);
    $$("#rangeSeg button").forEach((b) => b.classList.toggle("active", b.dataset.secs === wanted));
  }
  try {
    await loadDetail();
    await loadHistory();
  } catch (e) {
    if (e.status === 404) { location.href = "/"; return; }
  }

  $("#rangeSeg").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-secs]");
    if (!btn) return;
    $$("#rangeSeg button").forEach((b) => b.classList.toggle("active", b === btn));
    curSecs = parseInt(btn.dataset.secs, 10);
    // 同步到 URL,便于分享"某节点某时段"
    history.replaceState(null, "", location.pathname + "?secs=" + curSecs);
    await loadHistory();
  });

  wsConnect((m) => {
    if (m.type !== "metrics" || m.node_id !== NODE_ID) return;
    const x = m.latest;
    if (nodeInfo) { nodeInfo.online = true; nodeInfo.last_seen = m.ts; }
    renderStats({ ...nodeInfo, online: true, last_seen: m.ts, registered: true }, x);
    if (curSecs <= 21600) {
      charts.cpu.append(x.ts, [x.cpu_pct]);
      charts.mem.append(x.ts, [x.mem_used]);
      charts.net.append(x.ts, [x.net_rx_bps, x.net_tx_bps]);
      charts.io.append(x.ts, [x.disk_read_bps, x.disk_write_bps]);
      charts.load.append(x.ts, [x.load1]);
    }
  }, () => { loadHistory().catch(() => {}); }); // 断线重连后重拉历史,补上曲线缺口

  // ------- 管理操作(危险操作二次确认) -------
  $("#exportBtn").addEventListener("click", () => {
    const fmt = confirm("确定导出当前时间范围的数据?\n\n「确定」= CSV,「取消」再选 JSON") ? "csv" : "json";
    // 会话 Cookie 随同源请求携带,ReadAuth 放行;浏览器直接下载
    window.open("/api/v1/nodes/" + NODE_ID + "/export?secs=" + curSecs + "&format=" + fmt, "_blank");
  });

  $("#renameBtn").addEventListener("click", async () => {
    const name = prompt("新名称:", nodeInfo ? nodeInfo.name : "");
    if (!name) return;
    const grp = prompt("分组(留空为无):", nodeInfo && nodeInfo.grp || "") || "";
    const note = prompt("备注(留空为无):", nodeInfo && nodeInfo.note || "") || "";
    try {
      await api("POST", "/api/nodes/" + NODE_ID + "/rename", { name: name.trim(), grp: grp.trim(), note: note.trim() });
      await loadDetail();
    } catch (e) { alert(e.error || "失败"); }
  });

  $("#revokeBtn").addEventListener("click", async () => {
    if (!confirm("确认吊销该节点的 token?其 agent 将立即无法上报。")) return;
    try { await api("POST", "/api/nodes/" + NODE_ID + "/revoke"); await loadDetail(); alert("已吊销"); }
    catch (e) { alert(e.error || "失败"); }
  });

  $("#regenBtn").addEventListener("click", async () => {
    if (!confirm("重置将吊销旧 token 并生成新的一次性安装密钥,确认?")) return;
    try {
      const r = await api("POST", "/api/nodes/" + NODE_ID + "/regen_key");
      $("#newCmd").textContent = r.command;
      $("#cmdDlg").showModal();
      await loadDetail();
    } catch (e) { alert(e.error || "失败"); }
  });
  $("#copyNewCmd").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("#newCmd").textContent); } catch (_) {}
  });
  $("#closeCmdDlg").addEventListener("click", () => $("#cmdDlg").close());

  /* 远程升级(单节点):在线立即下发;若触发瞬间正在重连,进入 30 秒补发窗口,重连后自动补发。
     复用批量端点(action:"upgrade"),不新增接口。 */
  $("#upgradeBtn").addEventListener("click", async () => {
    if (!confirm("触发「" + (nodeInfo ? nodeInfo.name : NODE_ID) + "」远程升级 agent?")) return;
    try {
      const r = await api("POST", "/api/nodes/batch", { action: "upgrade", ids: [NODE_ID] });
      if (r.affected > 0) alert("已触发升级,实际是否成功需稍后核对 Agent 版本。");
      else alert("节点正在重连,升级请求已排入 30 秒补发窗口,重连后自动补发;如仍未生效可稍后重试。");
    } catch (e) { alert(e.error || "失败"); }
  });

  $("#deleteBtn").addEventListener("click", async () => {
    if (!confirm("确认删除节点及其全部历史数据?此操作不可恢复。")) return;
    if (!confirm("再次确认:删除「" + (nodeInfo ? nodeInfo.name : NODE_ID) + "」?")) return;
    try { await api("DELETE", "/api/nodes/" + NODE_ID); location.href = "/"; }
    catch (e) { alert(e.error || "失败"); }
  });
});
