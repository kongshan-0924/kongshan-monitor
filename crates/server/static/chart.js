/* 自写轻量 canvas 时间序列图(~4KB):零第三方依赖,完全可审计。
   特性:多序列折线+面积、自适应刻度、DPR 渲染、悬浮十字线与数值、主题联动。 */
"use strict";

function opChart(container, opts) {
  const series = opts.series; // [{label, colorVar, fill}]
  const yFmt = opts.yFmt || ((v) => String(Math.round(v)));
  const yMax = opts.yMax; // 可选固定上限(如 CPU 100)

  const canvas = document.createElement("canvas");
  container.appendChild(canvas);
  const tip = el("div", "chart-tip");
  container.appendChild(tip);
  const legend = el("div", "chart-legend");
  container.parentElement.appendChild(legend);

  const ctx = canvas.getContext("2d");
  let ts = [], data = series.map(() => []);
  let hoverX = -1;

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  function colors() {
    return series.map((s) => cssVar(s.colorVar || "--chart1"));
  }
  function rebuildLegend() {
    legend.replaceChildren();
    const cs = colors();
    series.forEach((s, i) => {
      const item = el("span", "lg");
      const sw = el("span", "sw");
      sw.style.background = cs[i];
      item.appendChild(sw);
      item.appendChild(el("span", null, s.label));
      legend.appendChild(item);
    });
  }
  rebuildLegend();

  function niceStep(range, n) {
    const raw = range / Math.max(1, n);
    const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
    for (const m of [1, 2, 5, 10]) {
      if (raw <= m * mag) return m * mag;
    }
    return 10 * mag;
  }

  function draw() {
    const rect = container.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const W = rect.width, H = rect.height;
    ctx.clearRect(0, 0, W, H);

    const padL = 46, padR = 8, padT = 8, padB = 20;
    const iw = W - padL - padR, ih = H - padT - padB;
    const lineCol = cssVar("--line"), mutedCol = cssVar("--muted");
    ctx.font = "10.5px -apple-system, sans-serif";

    if (ts.length < 2) {
      ctx.fillStyle = mutedCol;
      ctx.textAlign = "center";
      ctx.fillText("暂无数据", W / 2, H / 2);
      return;
    }

    let lo = 0, hi = yMax || 0;
    if (!yMax) {
      for (const arr of data) for (const v of arr) if (v != null && v > hi) hi = v;
      if (hi <= 0) hi = 1;
      hi *= 1.12;
    }
    const t0 = ts[0], t1 = ts[ts.length - 1], tr = Math.max(1, t1 - t0);
    const xOf = (t) => padL + ((t - t0) / tr) * iw;
    const yOf = (v) => padT + ih - ((v - lo) / (hi - lo)) * ih;

    // 水平网格 + Y 刻度
    const step = niceStep(hi - lo, 4);
    ctx.strokeStyle = lineCol;
    ctx.fillStyle = mutedCol;
    ctx.lineWidth = 1;
    ctx.textAlign = "right";
    for (let v = lo; v <= hi + 1e-9; v += step) {
      const y = yOf(v);
      if (y < padT - 1) break;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
      ctx.fillText(yFmt(v), padL - 6, y + 3.5);
    }
    // X 时间刻度
    ctx.textAlign = "center";
    const nx = Math.max(2, Math.floor(iw / 90));
    for (let i = 0; i <= nx; i++) {
      const t = t0 + (tr * i) / nx;
      const d = new Date(t * 1000);
      const label = tr > 86400 * 2
        ? (d.getMonth() + 1) + "/" + d.getDate()
        : String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
      ctx.fillText(label, xOf(t), H - 6);
    }

    // 序列
    const cs = colors();
    series.forEach((s, si) => {
      const arr = data[si];
      ctx.beginPath();
      let started = false;
      for (let i = 0; i < ts.length; i++) {
        const v = arr[i];
        if (v == null) { started = false; continue; }
        const x = xOf(ts[i]), y = yOf(Math.min(v, hi));
        if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = cs[si];
      ctx.lineWidth = 1.6;
      ctx.lineJoin = "round";
      ctx.stroke();
      if (s.fill) {
        ctx.lineTo(xOf(t1), yOf(lo));
        ctx.lineTo(xOf(ts.find((_, i) => arr[i] != null) ?? t0), yOf(lo));
        ctx.closePath();
        ctx.globalAlpha = 0.12;
        ctx.fillStyle = cs[si];
        ctx.fill();
        ctx.globalAlpha = 1;
      }
    });

    // 悬浮十字线
    if (hoverX >= 0) {
      let idx = 0, best = Infinity;
      for (let i = 0; i < ts.length; i++) {
        const d = Math.abs(xOf(ts[i]) - hoverX);
        if (d < best) { best = d; idx = i; }
      }
      const x = xOf(ts[idx]);
      ctx.strokeStyle = mutedCol;
      ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + ih); ctx.stroke();
      ctx.setLineDash([]);
      series.forEach((s, si) => {
        const v = data[si][idx];
        if (v == null) return;
        ctx.beginPath();
        ctx.arc(x, yOf(Math.min(v, hi)), 3, 0, Math.PI * 2);
        ctx.fillStyle = cs[si];
        ctx.fill();
      });
      tip.replaceChildren();
      tip.appendChild(el("div", "subtle", fmtTime(ts[idx])));
      series.forEach((s, si) => {
        const v = data[si][idx];
        tip.appendChild(el("div", null, s.label + ": " + (v == null ? "-" : yFmt(v))));
      });
      tip.style.display = "block";
      const tw = tip.offsetWidth;
      tip.style.left = Math.min(Math.max(0, x + 10), W - tw - 4) + "px";
      tip.style.top = "6px";
    } else {
      tip.style.display = "none";
    }
  }

  canvas.addEventListener("mousemove", (e) => {
    const r = canvas.getBoundingClientRect();
    hoverX = e.clientX - r.left;
    draw();
  });
  canvas.addEventListener("mouseleave", () => { hoverX = -1; draw(); });

  const ro = new ResizeObserver(draw);
  ro.observe(container);
  document.addEventListener("op-theme", () => { rebuildLegend(); draw(); });

  return {
    setData(newTs, newData) { ts = newTs; data = newData; draw(); },
    append(t, values, maxPoints) {
      ts.push(t);
      values.forEach((v, i) => data[i] && data[i].push(v));
      const cap = maxPoints || 720;
      if (ts.length > cap) {
        ts.splice(0, ts.length - cap);
        data.forEach((a) => a.splice(0, a.length - cap));
      }
      draw();
    },
  };
}
