/* 公开状态页:脱敏只读大盘(名称/分组/在线/CPU/内存/磁盘 百分比)。 */
"use strict";

const SLUG = (location.pathname.match(/^\/status\/([a-z0-9_-]{2,64})$/) || [])[1] || "";

function bar(label, p) {
  const wrap = el("div", "meter");
  const lab = el("div", "m-label");
  lab.appendChild(el("span", null, label));
  lab.appendChild(el("span", null, p.toFixed(0) + "%"));
  const b = el("div", "m-bar");
  const f = el("div", "m-fill" + (p > 90 ? " bad" : p > 70 ? " warn" : ""));
  f.style.width = Math.min(100, Math.max(0, p)).toFixed(1) + "%";
  b.appendChild(f);
  wrap.appendChild(lab); wrap.appendChild(b);
  return wrap;
}

async function load() {
  if (!SLUG) return;
  let d;
  try {
    const res = await fetch("/api/status/" + SLUG, { credentials: "omit" });
    if (!res.ok) { $("#foot").textContent = "状态页不可用"; return; }
    d = await res.json();
  } catch (_) { return; }

  const online = d.nodes.filter((n) => n.online).length;
  const box = $("#summary");
  box.replaceChildren();
  const card = (label, val, cls) => {
    const c = el("div", "sum" + (cls ? " " + cls : ""));
    c.appendChild(el("div", "sum-val", String(val)));
    c.appendChild(el("div", "sum-label", label));
    return c;
  };
  box.appendChild(card("节点", d.nodes.length));
  box.appendChild(card("在线", online, "ok"));
  box.appendChild(card("离线", d.nodes.length - online, (d.nodes.length - online) ? "bad" : ""));

  const grid = $("#grid");
  grid.replaceChildren();
  for (const n of d.nodes) {
    const c = el("div", "card node-card");
    const head = el("div", "nc-head");
    head.appendChild(el("span", "dot " + (n.online ? "on" : "off")));
    head.appendChild(el("span", "nc-name", n.name));
    if (n.grp) head.appendChild(el("span", "nc-grp", n.grp));
    c.appendChild(head);
    if (n.online) {
      c.appendChild(bar("CPU", n.cpu));
      c.appendChild(bar("内存", n.mem));
      c.appendChild(bar("磁盘", n.disk));
    } else {
      const s = el("div", "subtle", "离线"); s.style.padding = "14px 0"; c.appendChild(s);
    }
    grid.appendChild(c);
  }
  $("#foot").textContent = "更新于 " + fmtTime(d.now) + " · Outpost 哨站";
}

document.addEventListener("DOMContentLoaded", () => {
  load();
  setInterval(load, 15000);
});
