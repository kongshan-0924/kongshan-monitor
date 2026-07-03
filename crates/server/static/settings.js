/* 设置页:左分类导航 + 各功能区。 */
"use strict";

document.addEventListener("DOMContentLoaded", async () => {
  // ---------- 左侧分类导航:点击显示对应区 ----------
  const navLinks = $$("#setNav a");
  function showSection(id) {
    $$(".settings-content .card.pad").forEach((s) => s.classList.toggle("show", s.id === id));
    navLinks.forEach((a) => a.classList.toggle("active", a.dataset.target === id));
    window.scrollTo(0, 0);
  }
  navLinks.forEach((a) => a.addEventListener("click", () => showSection(a.dataset.target)));
  // 支持 #hash 直达
  if (location.hash) { const id = location.hash.slice(1); if (document.getElementById(id)) showSection(id); }

  // ---------- 外观主题 ----------
  function renderThemes() {
    const box = $("#themeSwatches");
    box.replaceChildren();
    const cur = currentAccent();
    for (const t of THEMES) {
      const b = el("button", "theme-swatch" + (t.id === cur ? " active" : ""));
      b.type = "button";
      const dot = el("span", "sw-dot"); dot.style.background = t.color;
      b.appendChild(dot); b.appendChild(el("span", "sw-name", t.name));
      b.addEventListener("click", () => { setAccent(t.id); renderThemes(); });
      box.appendChild(b);
    }
  }
  renderThemes();
  $$('#s-appearance [data-mode]').forEach((b) => b.addEventListener("click", () => {
    const m = b.dataset.mode;
    const root = document.documentElement;
    root.classList.remove("light", "dark");
    if (m === "light") { root.classList.add("light"); localStorage.setItem("op-theme", "light"); }
    else if (m === "dark") { root.classList.add("dark"); localStorage.setItem("op-theme", "dark"); }
    else { localStorage.removeItem("op-theme"); }
    document.dispatchEvent(new CustomEvent("op-theme"));
  }));

  // 公开状态页前缀 = 当前访问地址
  $("#statusPrefix").textContent = location.origin + "/status/";

  try {
    const s = await api("GET", "/api/settings");
    $("#interval").value = s.report_interval_secs;
    $("#retention").value = s.retention_days;
    renderStatusState(s.status_enabled, s.status_url);
  } catch (_) {}

  function renderStatusState(enabled, url) {
    $("#statusOn").classList.toggle("hidden", !enabled);
    $("#statusOff").classList.toggle("hidden", !!enabled);
    if (enabled && url) $("#statusUrl").textContent = url;
  }
  window.__renderStatusState = renderStatusState;

  $("#sysForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("#sysMsg");
    msg.textContent = "";
    try {
      await api("POST", "/api/settings", {
        report_interval_secs: parseInt($("#interval").value, 10),
        retention_days: parseInt($("#retention").value, 10),
      });
      msg.textContent = "已保存 ✓";
      setTimeout(() => { msg.textContent = ""; }, 2000);
    } catch (err) {
      msg.textContent = err.error || "保存失败";
    }
  });

  $("#pwForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("#pwMsg");
    msg.textContent = "";
    try {
      await api("POST", "/api/password", {
        old_password: $("#oldPw").value,
        new_password: $("#newPw").value,
      });
      alert("密码已修改,请重新登录");
      location.href = "/login";
    } catch (err) {
      msg.textContent = err.error || "修改失败";
    }
  });

  // ---------- 两步验证 ----------
  async function loadTfa() {
    const s = await api("GET", "/api/2fa/status");
    $("#tfaStatus").classList.add("hidden");
    $("#tfaOn").classList.toggle("hidden", !s.enabled);
    $("#tfaOff").classList.toggle("hidden", s.enabled);
  }
  loadTfa().catch(() => {});
  $("#tfaSetupBtn").addEventListener("click", async () => {
    try {
      const r = await api("POST", "/api/2fa/setup");
      $("#tfaSecret").textContent = r.secret;
      $("#tfaUri").textContent = "otpauth URI:" + r.uri;
      $("#tfaSetup").classList.remove("hidden");
    } catch (e) { alert(e.error || "失败"); }
  });
  $("#tfaEnableBtn").addEventListener("click", async () => {
    $("#tfaMsg").textContent = "";
    try {
      const r = await api("POST", "/api/2fa/enable", { code: $("#tfaCode").value.trim() });
      $("#tfaCodesList").textContent = r.recovery_codes.join("\n");
      $("#tfaCodes").classList.remove("hidden");
      $("#tfaSetup").classList.add("hidden");
      $("#tfaSetupBtn").classList.add("hidden");
    } catch (e) { $("#tfaMsg").textContent = e.error || "失败"; }
  });
  $("#tfaDisableBtn").addEventListener("click", async () => {
    $("#tfaDisMsg").textContent = "";
    try {
      await api("POST", "/api/2fa/disable", { password: $("#tfaDisPw").value, code: $("#tfaDisCode").value.trim() });
      alert("两步验证已停用"); loadTfa();
      $("#tfaDisPw").value = ""; $("#tfaDisCode").value = "";
    } catch (e) { $("#tfaDisMsg").textContent = e.error || "失败"; }
  });

  // ---------- 会话/设备 ----------
  async function loadSessions() {
    const d = await api("GET", "/api/sessions");
    const tbl = $("#sessTbl");
    tbl.replaceChildren();
    const head = el("tr");
    ["设备/UA", "IP", "登录时间", "操作"].forEach((h) => head.appendChild(el("th", null, h)));
    tbl.appendChild(head);
    for (const s of d.items) {
      const tr = el("tr");
      const ua = el("td");
      ua.appendChild(el("span", null, (s.user_agent || "未知").slice(0, 60)));
      if (s.current) ua.appendChild(el("span", "pill on", " 当前"));
      tr.appendChild(ua);
      tr.appendChild(el("td", null, s.ip || "-"));
      tr.appendChild(el("td", null, fmtTime(s.created_at)));
      const ops = el("td");
      if (!s.current) {
        const del = el("button", "btn danger xs", "撤销");
        del.addEventListener("click", async () => {
          await api("DELETE", "/api/sessions/" + s.token_hash); loadSessions();
        });
        ops.appendChild(del);
      } else { ops.appendChild(el("span", "subtle", "—")); }
      tr.appendChild(ops);
      tbl.appendChild(tr);
    }
  }
  loadSessions().catch(() => {});

  // ---------- 备份 ----------
  $("#backupBtn").addEventListener("click", () => { window.open("/api/backup", "_blank"); });

  // ---------- Agent 升级命令 ----------
  try {
    const u = await api("GET", "/api/upgrade_command");
    $("#upgradeCmd").textContent = u.command;
    $("#expVer").textContent = u.expected;
  } catch (_) { $("#upgradeCmd").textContent = "加载失败"; }
  $("#copyUpgrade").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("#upgradeCmd").textContent);
      $("#copyUpgrade").textContent = "已复制 ✓"; setTimeout(() => { $("#copyUpgrade").textContent = "复制命令"; }, 1500);
    } catch (_) {}
  });

  // ---------- 公开状态页(自定义后缀)----------
  $("#statusEnableBtn").addEventListener("click", async () => {
    $("#statusMsg").textContent = "";
    try {
      const r = await api("POST", "/api/status/enable", { slug: $("#statusSlug").value.trim() });
      renderStatusState(true, location.origin + "/status/" + r.slug);
    } catch (e) { $("#statusMsg").textContent = e.error || "失败"; }
  });
  $("#statusChangeBtn").addEventListener("click", () => {
    // 回到编辑态改地址(不影响已启用,直到点开启覆盖)
    $("#statusOn").classList.add("hidden");
    $("#statusOff").classList.remove("hidden");
  });
  $("#statusDisableBtn").addEventListener("click", async () => {
    if (!confirm("关闭后公开链接立即失效,确认?")) return;
    try { await api("POST", "/api/status/disable"); renderStatusState(false, ""); }
    catch (e) { alert(e.error || "失败"); }
  });

  // ---------- 审计导出 ----------
  $("#auditExportBtn").addEventListener("click", () => { window.open("/api/audit/export", "_blank"); });

  $("#logoutAllBtn").addEventListener("click", async () => {
    if (!confirm("确认使全部会话失效?所有已登录的浏览器都需要重新登录。")) return;
    try { await api("POST", "/api/logout_all"); } catch (_) {}
    location.href = "/login";
  });

  async function loadTokens() {
    const d = await api("GET", "/api/apitokens");
    const tbl = $("#tokenTbl");
    tbl.replaceChildren();
    const head = el("tr");
    ["名称", "创建时间", "最后使用", "操作"].forEach((h) => head.appendChild(el("th", null, h)));
    tbl.appendChild(head);
    for (const t of d.items) {
      const tr = el("tr");
      tr.appendChild(el("td", null, t.name));
      tr.appendChild(el("td", null, fmtTime(t.created_at)));
      tr.appendChild(el("td", null, t.last_used ? fmtTime(t.last_used) : "从未"));
      const ops = el("td");
      const del = el("button", "btn danger xs", "删除");
      del.addEventListener("click", async () => {
        if (!confirm("删除 Token「" + t.name + "」?使用它的外部系统将立即失效。")) return;
        await api("DELETE", "/api/apitokens/" + t.id); loadTokens();
      });
      ops.appendChild(del); tr.appendChild(ops);
      tbl.appendChild(tr);
    }
    if (!d.items.length) { const tr = el("tr"); const td = el("td", "subtle", "还没有 Token"); td.colSpan = 4; tr.appendChild(td); tbl.appendChild(tr); }
  }
  loadTokens();
  $("#addTokenBtn").addEventListener("click", async () => {
    const name = prompt("Token 名称(便于识别用途):", "prometheus");
    if (!name) return;
    try {
      const r = await api("POST", "/api/apitokens", { name: name.trim() });
      $("#tokenVal").textContent = r.token;
      $("#newToken").classList.remove("hidden");
      loadTokens();
    } catch (e) { alert(e.error || "创建失败"); }
  });

  try {
    const a = await api("GET", "/api/audit");
    const tbl = $("#auditTbl");
    const head = el("tr");
    ["时间", "用户", "来源 IP", "操作", "详情"].forEach((h) => head.appendChild(el("th", null, h)));
    tbl.appendChild(head);
    for (const it of a.items) {
      const tr = el("tr");
      tr.appendChild(el("td", null, fmtTime(it.ts)));
      tr.appendChild(el("td", null, it.username || "-"));
      tr.appendChild(el("td", null, it.ip || "-"));
      tr.appendChild(el("td", null, it.action));
      tr.appendChild(el("td", null, it.detail || ""));
      tbl.appendChild(tr);
    }
  } catch (_) {}
});
