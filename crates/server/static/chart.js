/* 自写轻量 canvas 时间序列图(~4KB):零第三方依赖,完全可审计。
   特性:多序列折线+面积、自适应刻度、DPR 渲染、悬浮十字线与数值、主题联动、
   平滑曲线/数据点两个全局展示选项(localStorage 记忆,所有图表联动)。 */
"use strict";

/* ---------- 全局图表展示选项(所有 opChart 实例共享联动) ---------- */
const CHART_PREFS = {
  smooth: localStorage.getItem("op-chart-smooth") !== "0", // 默认开
  dots: localStorage.getItem("op-chart-dots") === "1", // 默认关
};
const ALL_CHARTS = [];
function setChartPref(key, val) {
  CHART_PREFS[key] = val;
  localStorage.setItem("op-chart-" + key, val ? "1" : "0");
  ALL_CHARTS.forEach((c) => c.draw());
}
/* 页面里若有 #chartOptSeg 工具条(data-opt="smooth"/"dots" 按钮),自动接管其状态与点击。 */
function bindChartOptSeg() {
  const seg = document.getElementById("chartOptSeg");
  if (!seg) return;
  const btns = Array.from(seg.querySelectorAll("button[data-opt]"));
  const sync = () => btns.forEach((b) => b.classList.toggle("active", !!CHART_PREFS[b.dataset.opt]));
  sync();
  seg.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-opt]");
    if (!btn) return;
    setChartPref(btn.dataset.opt, !CHART_PREFS[btn.dataset.opt]);
    sync();
  });
}
document.addEventListener("DOMContentLoaded", bindChartOptSeg);

/* Catmull-Rom → 三次贝塞尔平滑曲线(张力 1/6,业界常用近似)。pts 至少 2 个点。 */
function drawCurve(ctx, pts, smooth) {
  if (pts.length < 2) return;
  ctx.moveTo(pts[0].x, pts[0].y);
  if (!smooth || pts.length < 3) {
    for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
    return;
  }
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] || p2;
    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    // 控制点 y 钳制到本段两端之间:三次贝塞尔受其控制点凸包约束,如此可保证
    // 曲线不越出 [min,max],消除样条过冲(尖峰鼓包 / 速率类曲线凹到 0 以下)。
    const lo = Math.min(p1.y, p2.y), hi = Math.max(p1.y, p2.y);
    const clampY = (y) => (y < lo ? lo : y > hi ? hi : y);
    const cp1y = clampY(p1.y + (p2.y - p0.y) / 6);
    const cp2y = clampY(p2.y - (p3.y - p1.y) / 6);
    ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y);
  }
}

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

    const padR = 8, padT = 8, padB = 20;
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
    const step = niceStep(hi - lo, 4);
    // 动态左边距:容纳最宽的 Y 轴标签(防 "386 KiB/s" 之类被裁切)
    let labelW = 0;
    for (let v = lo; v <= hi + 1e-9; v += step) {
      labelW = Math.max(labelW, ctx.measureText(yFmt(v)).width);
    }
    const padL = Math.max(44, Math.ceil(labelW) + 12);
    const iw = W - padL - padR, ih = H - padT - padB;
    const t0 = ts[0], t1 = ts[ts.length - 1], tr = Math.max(1, t1 - t0);
    const xOf = (t) => padL + ((t - t0) / tr) * iw;
    const yOf = (v) => padT + ih - ((v - lo) / (hi - lo)) * ih;

    // 水平网格 + Y 刻度
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

    // 序列:按连续无 null 的"段"分别绘制(可平滑曲线/可选数据点,各段各自补面)
    const cs = colors();
    series.forEach((s, si) => {
      const arr = data[si];
      const runs = [];
      let cur = [];
      for (let i = 0; i < ts.length; i++) {
        const v = arr[i];
        if (v == null) { if (cur.length) runs.push(cur); cur = []; continue; }
        cur.push({ x: xOf(ts[i]), y: yOf(Math.min(v, hi)) });
      }
      if (cur.length) runs.push(cur);

      ctx.strokeStyle = cs[si];
      ctx.lineWidth = 1.6;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      for (const run of runs) {
        ctx.beginPath();
        drawCurve(ctx, run, CHART_PREFS.smooth);
        ctx.stroke();
        if (s.fill) {
          ctx.lineTo(run[run.length - 1].x, yOf(lo));
          ctx.lineTo(run[0].x, yOf(lo));
          ctx.closePath();
          ctx.globalAlpha = 0.12;
          ctx.fillStyle = cs[si];
          ctx.fill();
          ctx.globalAlpha = 1;
        }
      }
      if (CHART_PREFS.dots) {
        ctx.fillStyle = cs[si];
        for (const run of runs) {
          for (const p of run) {
            ctx.beginPath();
            ctx.arc(p.x, p.y, 1.8, 0, Math.PI * 2);
            ctx.fill();
          }
        }
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

  const controller = {
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
    draw, // 供全局展示选项切换时统一重绘
  };
  ALL_CHARTS.push(controller);
  return controller;
}
