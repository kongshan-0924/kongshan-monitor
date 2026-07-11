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

/* ---------- 角色(轻量 RBAC):viewer 隐藏/跳过全部写操作入口 ----------
   真正的访问控制在服务端(SessionAdmin 提取器);这里只是 UI 层面按角色
   隐藏按钮,避免 viewer 点了却收到 403。缓存 in-flight promise,避免各页面
   脚本各自触发一次 /api/me。 */
let ROLE = "admin";
let _rolePromise = null;
function myRole() {
  if (!_rolePromise) {
    _rolePromise = (
      document.body.dataset.auth !== "1"
        ? Promise.resolve("admin")
        : api("GET", "/api/me").then((m) => m.role || "admin").catch(() => "admin")
    ).then((r) => {
      ROLE = r;
      document.body.classList.toggle("role-viewer", r === "viewer");
      return r;
    });
  }
  return _rolePromise;
}
function isViewer() {
  return ROLE === "viewer";
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
  if (d > 0) return d + "天" + h + "时";
  if (h > 0) return h + "时" + m + "分";
  return m + "分";
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

/* ---------- 告警桌面通知(本地开关) ---------- */
function desktopNotifyEnabled() {
  return localStorage.getItem("op-notify") === "1";
}
async function enableDesktopNotify() {
  if (!("Notification" in window)) return false;
  let perm = Notification.permission;
  if (perm !== "granted") { try { perm = await Notification.requestPermission(); } catch (_) { perm = "denied"; } }
  const ok = perm === "granted";
  localStorage.setItem("op-notify", ok ? "1" : "0");
  return ok;
}
let lastNotifyAt = 0;
function notifyDesktop(text) {
  if (!desktopNotifyEnabled() || !("Notification" in window) || Notification.permission !== "granted") return;
  const now = Date.now();
  if (now - lastNotifyAt < 1000) return; // 节流,防风暴
  lastNotifyAt = now;
  try { new Notification("Outpost 告警", { body: text, tag: "outpost-alert" }); } catch (_) {}
}

/* ---------- 主题(浅/深 + 配色) ---------- */
const THEMES = [
  { id: "apple", name: "默认", color: "#0071e3" },
  { id: "green", name: "森林绿", color: "#3e8e7e" },
  { id: "tech", name: "科技", color: "#35c5e0" },
  { id: "minimal", name: "极简", color: "#3a3a38" },
  { id: "soft", name: "柔和", color: "#e08a5c" },
  { id: "terminal", name: "终端", color: "#3ddc7a" },
  { id: "panel", name: "面板", color: "#6c5ce7" },
  { id: "ink-light", name: "水墨浅色", color: "#3f6b57" },
  { id: "ops-dark", name: "运维深色", color: "#46c08d" },
  { id: "astro", name: "观星", color: "#d4a94e" },
  { id: "aura", name: "流光", color: "#7c6cf0" },
];
function applyAccent(id) {
  document.documentElement.setAttribute("data-theme", id || "apple");
}
function currentAccent() {
  return localStorage.getItem("op-accent") || "apple";
}
function setAccent(id) {
  localStorage.setItem("op-accent", id);
  applyAccent(id);
  document.dispatchEvent(new CustomEvent("op-theme"));
}
(function initTheme() {
  const saved = localStorage.getItem("op-theme");
  if (saved === "dark") document.documentElement.classList.add("dark");
  if (saved === "light") document.documentElement.classList.add("light");
  applyAccent(currentAccent());
})();
/* 流光主题(aura)的光标跟随柔光:把指针在卡片内的相对位置写进 --gx/--gy,
   CSS 侧用它定位径向渐变。仅精确指针设备启用;非 aura 主题时零开销早退。 */
(function auraGlow() {
  if (!matchMedia("(pointer: fine)").matches) return;
  document.addEventListener("mousemove", (e) => {
    if (document.documentElement.getAttribute("data-theme") !== "aura") return;
    const t = e.target.closest(".card, .sum, .node-card, .stat, .chart-card");
    if (!t) return;
    const r = t.getBoundingClientRect();
    t.style.setProperty("--gx", (((e.clientX - r.left) / r.width) * 100).toFixed(1) + "%");
    t.style.setProperty("--gy", (((e.clientY - r.top) / r.height) * 100).toFixed(1) + "%");
  }, { passive: true });
})();
function bindChrome() {
  myRole();
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
function wsConnect(onMsg, onReconnect) {
  let delay = 1000;
  let closed = false;
  let opened = false; // 是否曾经连上过:用于区分首次连接与断线重连
  function open() {
    if (closed) return;
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    const ws = new WebSocket(proto + location.host + "/ws/ui");
    ws.onopen = () => {
      delay = 1000;
      // 重连成功(非首次)后回调:让页面重新拉一次快照,避免断线期间实时值冻结成旧值
      if (opened && onReconnect) onReconnect();
      opened = true;
    };
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
