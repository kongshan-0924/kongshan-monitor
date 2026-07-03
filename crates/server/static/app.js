/* 公共工具:API 封装、主题、WS、格式化。
   安全纪律:所有动态数据仅通过 textContent / createElement 渲染,
   全站不使用 innerHTML 插入变量(存储型 XSS 第二道防线)。 */
"use strict";

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

/* ---------- API ---------- */
async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: {
      "x-op": "1",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    if (document.body.dataset.auth === "1") location.href = "/login";
    throw { status: 401, error: "未认证" };
  }
  if (res.status === 204) return null;
  let data = null;
  try { data = await res.json(); } catch (_) { /* 非 JSON 响应 */ }
  if (!res.ok) throw { status: res.status, error: (data && data.error) || "请求失败" };
  return data;
}

/* ---------- 元素构造(XSS 安全) ---------- */
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}

/* ---------- 格式化 ---------- */
function fmtBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "-";
  const u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)) + " " + u[i];
}
function fmtBps(n) {
  if (!Number.isFinite(n) || n < 0) return "-";
  return fmtBytes(n) + "/s";
}
function fmtDur(secs) {
  if (!Number.isFinite(secs) || secs < 0) return "-";
  const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
  if (d > 0) return d + " 天 " + h + " 时";
  if (h > 0) return h + " 时 " + m + " 分";
  return m + " 分";
}
function fmtTime(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}
function timeAgo(ts) {
  if (!ts) return "从未";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 5) return "刚刚";
  if (s < 60) return s + " 秒前";
  if (s < 3600) return Math.floor(s / 60) + " 分钟前";
  if (s < 86400) return Math.floor(s / 3600) + " 小时前";
  return Math.floor(s / 86400) + " 天前";
}
function pct(used, total) {
  if (!total) return 0;
  return Math.min(100, Math.max(0, (used / total) * 100));
}

/* ---------- 主题 ---------- */
(function initTheme() {
  const saved = localStorage.getItem("op-theme");
  if (saved === "dark") document.documentElement.classList.add("dark");
  if (saved === "light") document.documentElement.classList.add("light");
})();
function bindChrome() {
  const tb = $("#themeBtn");
  if (tb) tb.addEventListener("click", () => {
    const root = document.documentElement;
    const dark = root.classList.contains("dark") ||
      (!root.classList.contains("light") && matchMedia("(prefers-color-scheme: dark)").matches);
    root.classList.toggle("dark", !dark);
    root.classList.toggle("light", dark);
    localStorage.setItem("op-theme", dark ? "light" : "dark");
    document.dispatchEvent(new CustomEvent("op-theme"));
  });
  const lb = $("#logoutBtn");
  if (lb) lb.addEventListener("click", async () => {
    try { await api("POST", "/api/logout"); } catch (_) {}
    location.href = "/login";
  });
}
document.addEventListener("DOMContentLoaded", bindChrome);

/* ---------- WebSocket(自动重连) ---------- */
function wsConnect(onMsg) {
  let delay = 1000;
  let closed = false;
  function open() {
    if (closed) return;
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    const ws = new WebSocket(proto + location.host + "/ws/ui");
    ws.onopen = () => { delay = 1000; };
    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string" || ev.data.length > 65536) return;
      let m = null;
      try { m = JSON.parse(ev.data); } catch (_) { return; }
      if (m && typeof m === "object") onMsg(m);
    };
    ws.onclose = () => {
      if (closed) return;
      setTimeout(open, delay);
      delay = Math.min(delay * 2, 15000);
    };
    ws.onerror = () => ws.close();
  }
  open();
  return () => { closed = true; };
}
