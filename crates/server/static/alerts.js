/* 告警页:事件、规则(分级)、渠道(含 SMTP,按严重度路由)、静默窗口、重复提醒。
   全部 textContent 渲染,不使用 innerHTML。 */
"use strict";

const METRIC_LABEL = {
  cpu_pct: "CPU 使用率", mem_pct: "内存使用率", disk_pct: "磁盘使用率",
  swap_pct: "Swap 使用率", load1: "1 分钟负载", cpu_temp: "CPU 温度",
  tcp_conns: "TCP 连接数", inode_pct: "inode 使用率",
  services_down: "异常服务数", offline: "节点离线",
};
const CMP = { gt: ">", gte: "≥", lt: "<", lte: "≤" };
const ROC_METRICS = ["cpu_pct", "mem_pct", "disk_pct", "swap_pct", "load1"];
function fmtRocWindow(secs) {
  if (secs >= 3600 && secs % 3600 === 0) return (secs / 3600) + " 小时";
  return Math.round(secs / 60) + " 分钟";
}
const SEV_LABEL = { info: "信息", warning: "警告", critical: "严重" };
const SEV_CLASS = { info: "sev-info", warning: "sev-warn", critical: "sev-crit" };

function th(row, labels) { labels.forEach((l) => row.appendChild(el("th", null, l))); }
function sevBadge(s) { return el("span", "spill " + (SEV_CLASS[s] || "sev-warn"), SEV_LABEL[s] || s); }

let EV_PAGE = 0;
async function loadEvents() {
  const d = await api("GET", "/api/alerts/events?page=" + EV_PAGE);
  const tbl = $("#eventTbl");
  tbl.replaceChildren();
  const head = el("tr"); th(head, ["状态", "节点", "规则", "详情", "开始", "恢复"]); tbl.appendChild(head);
  for (const e of d.items) {
    const tr = el("tr");
    const st = el("td");
    const dot = el("span", "dot " + (e.firing ? "off" : "on"));
    st.appendChild(dot); st.appendChild(el("span", null, " " + (e.firing ? "告警中" : "已恢复")));
    tr.appendChild(st);
    const evNodeTd = el("td", "nowrap", e.node_name || ("#" + e.node_id)); if (e.node_name) evNodeTd.title = e.node_name; tr.appendChild(evNodeTd);
    const evRuleTd = el("td", "nowrap", e.rule_name || ("#" + e.rule_id)); if (e.rule_name) evRuleTd.title = e.rule_name; tr.appendChild(evRuleTd);
    const msgTd = el("td", "nowrap", e.message); msgTd.title = e.message; tr.appendChild(msgTd);
    tr.appendChild(el("td", "nowrap", fmtTime(e.started_at)));
    tr.appendChild(el("td", "nowrap", e.resolved_at ? fmtTime(e.resolved_at) : "—"));
    tbl.appendChild(tr);
  }
  if (!d.items.length) { const tr = el("tr"); const td = el("td", "subtle", "暂无告警事件"); td.colSpan = 6; tr.appendChild(td); tbl.appendChild(tr); }
  $("#firingCount").textContent = d.firing > 0 ? ("🔴 " + d.firing + " 条告警中") : "✓ 一切正常";
  updateBadge(d.firing);
  renderEventPager(d);
}

function renderEventPager(d) {
  const pager = $("#eventPager");
  if (!pager) return;
  pager.replaceChildren();
  const size = d.page_size || 50;
  const pages = Math.max(1, Math.ceil((d.total || 0) / size));
  const cur = d.page || 0;
  const prev = el("button", "btn ghost sm", "‹ 上一页"); prev.type = "button"; prev.disabled = cur <= 0;
  prev.addEventListener("click", () => { EV_PAGE = Math.max(0, EV_PAGE - 1); loadEvents().catch(() => {}); });
  const next = el("button", "btn ghost sm", "下一页 ›"); next.type = "button"; next.disabled = cur >= pages - 1;
  next.addEventListener("click", () => { EV_PAGE += 1; loadEvents().catch(() => {}); });
  pager.appendChild(prev);
  pager.appendChild(el("span", "subtle", "第 " + (cur + 1) + " / " + pages + " 页 · 共 " + (d.total || 0) + " 条"));
  pager.appendChild(next);
}

function updateBadge(n) {
  const b = $("#navBadge");
  if (!b) return;
  b.textContent = String(n);
  b.classList.toggle("hidden", !n);
}

async function loadRules(nodes) {
  const d = await api("GET", "/api/alerts/rules");
  const tbl = $("#ruleTbl");
  tbl.replaceChildren();
  const admin = !isViewer();
  const head = el("tr"); th(head, ["名称", "级别", "条件", "持续", "范围", "状态"].concat(admin ? ["操作"] : [])); tbl.appendChild(head);
  for (const r of d.items) {
    const tr = el("tr");
    const ruleNameTd = el("td", "nowrap", r.name); ruleNameTd.title = r.name; tr.appendChild(ruleNameTd);
    const sevTd = el("td"); sevTd.appendChild(sevBadge(r.severity || "warning")); tr.appendChild(sevTd);
    let cond;
    if (r.metric === "offline") cond = "离线";
    else if (r.comparator === "roc") cond = METRIC_LABEL[r.metric] + " 变化 ≥ " + r.threshold + "(" + fmtRocWindow(r.roc_window_secs) + "内)";
    else cond = METRIC_LABEL[r.metric] + " " + (CMP[r.comparator] || ">") + " " + r.threshold;
    const condTd = el("td", "nowrap", cond); condTd.title = cond; tr.appendChild(condTd);
    tr.appendChild(el("td", "nowrap", r.duration_secs + "s"));
    const scopeTd = el("td", "nowrap", r.node_name || "所有节点"); if (r.node_name) scopeTd.title = r.node_name; tr.appendChild(scopeTd);
    const stTd = el("td");
    stTd.appendChild(el("span", "pill " + (r.enabled ? "on" : "off"), r.enabled ? "启用" : "停用"));
    tr.appendChild(stTd);
    if (admin) {
      const ops = el("td", "ops");
      const tog = el("button", "btn ghost xs", r.enabled ? "停用" : "启用");
      tog.addEventListener("click", async () => { await api("POST", "/api/alerts/rules/" + r.id + "/toggle"); loadRules(nodes); });
      const del = el("button", "btn danger xs", "删除");
      del.addEventListener("click", async () => {
        if (!confirm("删除规则「" + r.name + "」?")) return;
        await api("DELETE", "/api/alerts/rules/" + r.id); loadRules(nodes);
      });
      ops.appendChild(tog); ops.appendChild(del); tr.appendChild(ops);
    }
    tbl.appendChild(tr);
  }
  if (!d.items.length) { const tr = el("tr"); const td = el("td", "subtle", admin ? "还没有规则,点「新增规则」开始" : "还没有规则"); td.colSpan = admin ? 7 : 6; tr.appendChild(td); tbl.appendChild(tr); }
}

async function loadChannels() {
  const d = await api("GET", "/api/alerts/channels");
  const tbl = $("#chanTbl");
  tbl.replaceChildren();
  const admin = !isViewer();
  const head = el("tr"); th(head, ["名称", "类型", "地址", "接收级别"].concat(admin ? ["操作"] : [])); tbl.appendChild(head);
  for (const c of d.items) {
    const tr = el("tr");
    const chanNameTd = el("td", "nowrap", c.name); chanNameTd.title = c.name; tr.appendChild(chanNameTd);
    tr.appendChild(el("td", "nowrap", c.kind));
    const urlTd = el("td", "nowrap nowrap-tight", c.url); urlTd.title = c.url; tr.appendChild(urlTd);
    tr.appendChild(el("td", "nowrap", "≥ " + (SEV_LABEL[c.min_severity] || c.min_severity || "信息")));
    if (admin) {
      const ops = el("td", "ops");
      const test = el("button", "btn ghost xs", "测试");
      test.addEventListener("click", async () => {
        test.disabled = true; test.textContent = "发送中…";
        try { await api("POST", "/api/alerts/channels/" + c.id + "/test"); alert("测试通知已发送成功 ✅"); }
        catch (e) { alert("测试失败:" + (e.error || "")); }
        finally { test.disabled = false; test.textContent = "测试"; }
      });
      const del = el("button", "btn danger xs", "删除");
      del.addEventListener("click", async () => {
        if (!confirm("删除渠道「" + c.name + "」?")) return;
        await api("DELETE", "/api/alerts/channels/" + c.id); loadChannels();
      });
      ops.appendChild(test); ops.appendChild(del); tr.appendChild(ops);
    }
    tbl.appendChild(tr);
  }
  if (!d.items.length) { const tr = el("tr"); const td = el("td", "subtle", "还没有通知渠道"); td.colSpan = admin ? 5 : 4; tr.appendChild(td); tbl.appendChild(tr); }
}

async function loadSilences() {
  const d = await api("GET", "/api/alerts/silences");
  const tbl = $("#silenceTbl");
  tbl.replaceChildren();
  const admin = !isViewer();
  const head = el("tr"); th(head, ["状态", "节点", "规则", "原因", "结束于"].concat(admin ? ["操作"] : [])); tbl.appendChild(head);
  for (const s of d.items) {
    const tr = el("tr");
    tr.appendChild(el("td", "nowrap", s.active ? "生效中" : "未开始"));
    const silNodeTxt = s.node_id ? (s.node_name || ("#" + s.node_id)) : "所有节点";
    const silNodeTd = el("td", "nowrap", silNodeTxt); silNodeTd.title = silNodeTxt; tr.appendChild(silNodeTd);
    const silRuleTxt = s.rule_id ? (s.rule_name || ("#" + s.rule_id)) : "所有规则";
    const silRuleTd = el("td", "nowrap", silRuleTxt); silRuleTd.title = silRuleTxt; tr.appendChild(silRuleTd);
    const reasonTd = el("td", "nowrap", s.reason || "—"); if (s.reason) reasonTd.title = s.reason; tr.appendChild(reasonTd);
    tr.appendChild(el("td", "nowrap", fmtTime(s.end_ts)));
    if (admin) {
      const ops = el("td", "ops");
      const del = el("button", "btn danger xs", "结束");
      del.addEventListener("click", async () => { await api("DELETE", "/api/alerts/silences/" + s.id); loadSilences(); });
      ops.appendChild(del); tr.appendChild(ops);
    }
    tbl.appendChild(tr);
  }
  if (!d.items.length) { const tr = el("tr"); const td = el("td", "subtle", "当前没有静默窗口"); td.colSpan = admin ? 6 : 5; tr.appendChild(td); tbl.appendChild(tr); }
}

function fillNodeSelect(sel, nodes) {
  for (const n of nodes) {
    const o = document.createElement("option");
    o.value = String(n.id); o.textContent = n.name;
    sel.appendChild(o);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  await myRole();
  let nodes = [];
  try {
    const nd = await api("GET", "/api/nodes");
    nodes = nd.nodes || [];
    fillNodeSelect($("#rNode"), nodes);
    fillNodeSelect($("#sNode"), nodes);
  } catch (_) {}

  // allSettled 而非 all:任一接口失败也不中断后续事件绑定(否则整页交互瘫痪,需手动刷新)。
  await Promise.allSettled([loadEvents(), loadRules(nodes), loadChannels(), loadSilences()]);

  $("#clearEventsBtn").addEventListener("click", async () => {
    if (!confirm("清理全部「已恢复」的历史告警事件?仍在触发中的会保留。")) return;
    try { await api("POST", "/api/alerts/events/clear"); EV_PAGE = 0; await loadEvents(); }
    catch (e) { alert(e.error || "清理失败"); }
  });

  // 重复提醒设置
  try {
    const rn = await api("GET", "/api/alerts/renotify");
    $("#renotifySel").value = String(rn.secs || 0);
  } catch (_) {}
  $("#renotifySel").addEventListener("change", async () => {
    try {
      await api("POST", "/api/alerts/renotify", { secs: parseInt($("#renotifySel").value, 10) || 0 });
      $("#renotifyMsg").textContent = "已保存 ✓";
      setTimeout(() => { $("#renotifyMsg").textContent = ""; }, 2000);
    } catch (e) { $("#renotifyMsg").textContent = e.error || "保存失败"; }
  });

  // 指标为离线时隐藏阈值行;比较符为变化率时显示窗口选择,并将指标限定为支持的核心 5 项
  function syncRuleForm() {
    const metric = $("#rMetric").value;
    const isRoc = $("#rComparator").value === "roc";
    $("#threshRow").classList.toggle("hidden", metric === "offline");
    $("#offlineHint").classList.toggle("hidden", metric !== "offline");
    // 离线规则给更宽容的默认容忍时长(适应云服务器抖动),仅在仍是通用默认值时替换,不覆盖用户改动
    const dur = $("#rDuration");
    if (metric === "offline" && (dur.value === "" || dur.value === "60")) dur.value = "120";
    $("#rocWindowRow").classList.toggle("hidden", !isRoc);
    $("#rThresholdLabel").firstChild.textContent = isRoc ? "变化幅度阈值 " : "阈值 ";
    for (const opt of $("#rMetric").options) {
      opt.disabled = isRoc && !ROC_METRICS.includes(opt.value);
    }
    if (isRoc && !ROC_METRICS.includes(metric)) $("#rMetric").value = "cpu_pct";
  }
  $("#rMetric").addEventListener("change", syncRuleForm);
  $("#rComparator").addEventListener("change", syncRuleForm);

  $("#addRuleBtn").addEventListener("click", () => {
    $("#ruleMsg").textContent = ""; $("#ruleForm").reset(); syncRuleForm(); $("#ruleDlg").showModal();
  });
  $("#ruleForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault();
    const metric = $("#rMetric").value;
    const comparator = $("#rComparator").value;
    const body = {
      name: $("#rName").value.trim(),
      metric,
      comparator,
      threshold: metric === "offline" ? 0 : parseFloat($("#rThreshold").value),
      duration_secs: parseInt($("#rDuration").value, 10) || 0,
      node_id: $("#rNode").value ? parseInt($("#rNode").value, 10) : null,
      severity: $("#rSeverity").value,
      roc_window_secs: comparator === "roc" ? parseInt($("#rRocWindow").value, 10) : 0,
    };
    try {
      await api("POST", "/api/alerts/rules", body);
      $("#ruleDlg").close(); $("#ruleForm").reset();
      loadRules(nodes);
    } catch (err) { $("#ruleMsg").textContent = err.error || "创建失败"; }
  });

  // 渠道类型切换:显示对应字段
  const KIND_HINT = {
    webhook: ["Webhook URL(https)", "https://open.feishu.cn/open-apis/bot/v2/hook/..."],
    telegram: ["Bot Token", "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"],
    bark: ["Bark 推送地址(https)", "https://api.day.app/你的Key"],
  };
  function syncKind() {
    const k = $("#cKind").value;
    const isSmtp = k === "smtp";
    const isTg = k === "telegram";
    $("#cUrlLabel").classList.toggle("hidden", isSmtp);
    $("#cTargetLabel").classList.toggle("hidden", isSmtp || !isTg);
    $("#smtpFields").classList.toggle("hidden", !isSmtp);
    if (!isSmtp) {
      const [label, ph] = KIND_HINT[k];
      $("#cUrlLabel").childNodes[0].nodeValue = label + " ";
      $("#cUrl").placeholder = ph;
    }
  }
  $("#cKind").addEventListener("change", syncKind);

  $("#addChanBtn").addEventListener("click", () => { $("#chanMsg").textContent = ""; syncKind(); $("#chanDlg").showModal(); });
  $("#chanForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault();
    const kind = $("#cKind").value;
    const body = { name: $("#cName").value.trim(), kind, min_severity: $("#cMinSev").value };
    if (kind === "smtp") {
      body.smtp_host = $("#cSmtpHost").value.trim();
      body.smtp_port = parseInt($("#cSmtpPort").value, 10) || 465;
      body.smtp_user = $("#cSmtpUser").value;
      body.smtp_pass = $("#cSmtpPass").value;
      body.smtp_from = $("#cSmtpFrom").value.trim();
      body.smtp_to = $("#cSmtpTo").value.trim();
    } else {
      body.url = $("#cUrl").value.trim();
      body.target = $("#cTarget").value.trim();
    }
    try {
      await api("POST", "/api/alerts/channels", body);
      $("#chanDlg").close(); $("#chanForm").reset();
      loadChannels();
    } catch (err) { $("#chanMsg").textContent = err.error || "保存失败"; }
  });

  // 静默窗口
  $("#addSilenceBtn").addEventListener("click", async () => {
    $("#silenceMsg").textContent = "";
    // 填充规则下拉(每次打开刷新)
    const sel = $("#sRule");
    sel.replaceChildren();
    const opt0 = document.createElement("option"); opt0.value = ""; opt0.textContent = "所有规则"; sel.appendChild(opt0);
    try {
      const rd = await api("GET", "/api/alerts/rules");
      for (const r of rd.items) {
        const o = document.createElement("option"); o.value = String(r.id); o.textContent = r.name; sel.appendChild(o);
      }
    } catch (_) {}
    $("#silenceDlg").showModal();
  });
  $("#silenceForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault();
    const body = {
      node_id: $("#sNode").value ? parseInt($("#sNode").value, 10) : null,
      rule_id: $("#sRule").value ? parseInt($("#sRule").value, 10) : null,
      duration_secs: parseInt($("#sDuration").value, 10),
      reason: $("#sReason").value.trim(),
    };
    try {
      await api("POST", "/api/alerts/silences", body);
      $("#silenceDlg").close(); $("#silenceForm").reset();
      loadSilences();
    } catch (err) { $("#silenceMsg").textContent = err.error || "创建失败"; }
  });

  // 桌面通知开关
  function syncNotifyBtn() {
    const on = desktopNotifyEnabled() && ("Notification" in window) && Notification.permission === "granted";
    $("#notifyBtn").textContent = on ? "桌面通知:已开启" : "开启桌面通知";
    $("#notifyBtn").classList.toggle("primary", on);
  }
  syncNotifyBtn();
  $("#notifyBtn").addEventListener("click", async () => {
    if (desktopNotifyEnabled()) { localStorage.setItem("op-notify", "0"); }
    else { await enableDesktopNotify(); }
    syncNotifyBtn();
  });

  // 实时:收到 alert 推送即刷新事件与角标;firing 时桌面通知
  wsConnect((m) => { if (m.type === "alert") { loadEvents(); if (m.firing) notifyDesktop(m.text); } });
  setInterval(loadEvents, 30000);
});
