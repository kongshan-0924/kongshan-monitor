/* 告警页:事件列表、规则 CRUD、渠道 CRUD + 测试。全部 textContent 渲染。 */
"use strict";

const METRIC_LABEL = {
  cpu_pct: "CPU 使用率", mem_pct: "内存使用率", disk_pct: "磁盘使用率",
  swap_pct: "Swap 使用率", load1: "1 分钟负载", offline: "节点离线",
};

function th(row, labels) { labels.forEach((l) => row.appendChild(el("th", null, l))); }

async function loadEvents() {
  const d = await api("GET", "/api/alerts/events");
  const tbl = $("#eventTbl");
  tbl.replaceChildren();
  const head = el("tr"); th(head, ["状态", "节点", "规则", "详情", "开始", "恢复"]); tbl.appendChild(head);
  for (const e of d.items) {
    const tr = el("tr");
    const st = el("td");
    const dot = el("span", "dot " + (e.firing ? "off" : "on"));
    st.appendChild(dot); st.appendChild(el("span", null, " " + (e.firing ? "告警中" : "已恢复")));
    tr.appendChild(st);
    tr.appendChild(el("td", null, e.node_name || ("#" + e.node_id)));
    tr.appendChild(el("td", null, e.rule_name || ("#" + e.rule_id)));
    tr.appendChild(el("td", null, e.message));
    tr.appendChild(el("td", null, fmtTime(e.started_at)));
    tr.appendChild(el("td", null, e.resolved_at ? fmtTime(e.resolved_at) : "—"));
    tbl.appendChild(tr);
  }
  if (!d.items.length) { const tr = el("tr"); const td = el("td", "subtle", "暂无告警事件"); td.colSpan = 6; tr.appendChild(td); tbl.appendChild(tr); }
  $("#firingCount").textContent = d.firing > 0 ? ("🔴 " + d.firing + " 条告警中") : "✓ 一切正常";
  updateBadge(d.firing);
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
  const head = el("tr"); th(head, ["名称", "条件", "持续", "范围", "状态", "操作"]); tbl.appendChild(head);
  for (const r of d.items) {
    const tr = el("tr");
    tr.appendChild(el("td", null, r.name));
    const cond = r.metric === "offline"
      ? "离线"
      : METRIC_LABEL[r.metric] + " " + (r.comparator === "lt" ? "<" : ">") + " " + r.threshold;
    tr.appendChild(el("td", null, cond));
    tr.appendChild(el("td", null, r.duration_secs + "s"));
    tr.appendChild(el("td", null, r.node_name || "所有节点"));
    const stTd = el("td");
    const badge = el("span", "pill " + (r.enabled ? "on" : "off"), r.enabled ? "启用" : "停用");
    stTd.appendChild(badge); tr.appendChild(stTd);
    const ops = el("td");
    const tog = el("button", "btn ghost xs", r.enabled ? "停用" : "启用");
    tog.addEventListener("click", async () => { await api("POST", "/api/alerts/rules/" + r.id + "/toggle"); loadRules(nodes); });
    const del = el("button", "btn danger xs", "删除");
    del.addEventListener("click", async () => {
      if (!confirm("删除规则「" + r.name + "」?")) return;
      await api("DELETE", "/api/alerts/rules/" + r.id); loadRules(nodes);
    });
    ops.appendChild(tog); ops.appendChild(del); tr.appendChild(ops);
    tbl.appendChild(tr);
  }
  if (!d.items.length) { const tr = el("tr"); const td = el("td", "subtle", "还没有规则,点「新增规则」开始"); td.colSpan = 6; tr.appendChild(td); tbl.appendChild(tr); }
}

async function loadChannels() {
  const d = await api("GET", "/api/alerts/channels");
  const tbl = $("#chanTbl");
  tbl.replaceChildren();
  const head = el("tr"); th(head, ["名称", "类型", "地址", "操作"]); tbl.appendChild(head);
  for (const c of d.items) {
    const tr = el("tr");
    tr.appendChild(el("td", null, c.name));
    tr.appendChild(el("td", null, c.kind));
    tr.appendChild(el("td", null, c.url));
    const ops = el("td");
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
    tbl.appendChild(tr);
  }
  if (!d.items.length) { const tr = el("tr"); const td = el("td", "subtle", "还没有通知渠道"); td.colSpan = 4; tr.appendChild(td); tbl.appendChild(tr); }
}

document.addEventListener("DOMContentLoaded", async () => {
  let nodes = [];
  try {
    const nd = await api("GET", "/api/nodes");
    nodes = nd.nodes || [];
    const sel = $("#rNode");
    for (const n of nodes) {
      const o = document.createElement("option");
      o.value = String(n.id); o.textContent = n.name;
      sel.appendChild(o);
    }
  } catch (_) {}

  await Promise.all([loadEvents(), loadRules(nodes), loadChannels()]);

  // 指标为离线时隐藏阈值行
  $("#rMetric").addEventListener("change", () => {
    $("#threshRow").classList.toggle("hidden", $("#rMetric").value === "offline");
  });

  $("#addRuleBtn").addEventListener("click", () => { $("#ruleMsg").textContent = ""; $("#ruleDlg").showModal(); });
  $("#ruleForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault();
    const metric = $("#rMetric").value;
    const body = {
      name: $("#rName").value.trim(),
      metric,
      comparator: $("#rComparator").value,
      threshold: metric === "offline" ? 0 : parseFloat($("#rThreshold").value),
      duration_secs: parseInt($("#rDuration").value, 10) || 0,
      node_id: $("#rNode").value ? parseInt($("#rNode").value, 10) : null,
    };
    try {
      await api("POST", "/api/alerts/rules", body);
      $("#ruleDlg").close(); $("#ruleForm").reset();
      loadRules(nodes);
    } catch (err) { $("#ruleMsg").textContent = err.error || "创建失败"; }
  });

  const KIND_HINT = {
    webhook: ["Webhook URL(https)", "https://open.feishu.cn/open-apis/bot/v2/hook/...", false],
    telegram: ["Bot Token", "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11", true],
    bark: ["Bark 推送地址(https)", "https://api.day.app/你的Key", false],
  };
  function syncKind() {
    const k = $("#cKind").value;
    const [label, ph, needTarget] = KIND_HINT[k];
    $("#cUrlLabel").childNodes[0].nodeValue = label + " ";
    $("#cUrl").placeholder = ph;
    $("#cTargetLabel").classList.toggle("hidden", !needTarget);
  }
  $("#cKind").addEventListener("change", syncKind);

  $("#addChanBtn").addEventListener("click", () => { $("#chanMsg").textContent = ""; syncKind(); $("#chanDlg").showModal(); });
  $("#chanForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault();
    try {
      await api("POST", "/api/alerts/channels", {
        name: $("#cName").value.trim(),
        kind: $("#cKind").value,
        url: $("#cUrl").value.trim(),
        target: $("#cTarget").value.trim(),
      });
      $("#chanDlg").close(); $("#chanForm").reset();
      loadChannels();
    } catch (err) { $("#chanMsg").textContent = err.error || "保存失败"; }
  });

  // 实时:收到 alert 推送即刷新事件与角标
  wsConnect((m) => { if (m.type === "alert") loadEvents(); });
  setInterval(loadEvents, 30000);
});
