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

/* 把原始秒步长吸附到"整"的时间刻度,让 X 轴落在整点/整 5·15·30 分/整天上。 */
const TIME_STEPS = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400,
  2 * 86400, 7 * 86400, 14 * 86400, 30 * 86400];
function niceTimeStep(sec) {
  for (const s of TIME_STEPS) if (sec <= s) return s;
  return TIME_STEPS[TIME_STEPS.length - 1];
}
/* CSS 颜色(#rgb/#rrggbb/rgb())→ 带 alpha 的 rgba,用于面积渐变填充;识别不了则原样返回。 */
function withAlpha(c, a) {
  c = (c || "").trim();
  if (c[0] === "#") {
    let h = c.slice(1);
    if (h.length === 3) h = h.split("").map((x) => x + x).join("");
    const n = parseInt(h, 16);
    if (!Number.isNaN(n)) return "rgba(" + ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
  }
  const m = c.match(/rgba?\(([^)]+)\)/);
  if (m) { const p = m[1].split(",").map((x) => x.trim()); return "rgba(" + p[0] + "," + p[1] + "," + p[2] + "," + a + ")"; }
  return c;
}

function opChart(container, opts) {
  const series = opts.series; // [{label, colorVar, fill}]
  const yFmt = opts.yFmt || ((v) => String(Math.round(v)));
  const yMax = opts.yMax; // 可选固定上限(如 CPU 100)
  let thresholds = opts.thresholds || []; // [{value, label?}] 告警阈值横虚线(可后设)

  const canvas = document.createElement("canvas");
  container.appendChild(canvas);
  const tip = el("div", "chart-tip");
  container.appendChild(tip);
  const legend = el("div", "chart-legend");
  container.parentElement.appendChild(legend);

  const ctx = canvas.getContext("2d");
  let ts = [], data = series.map(() => []);
  let bands = null;   // 每序列可选的"桶内峰值"数组(与 data 平行),画均值~峰值半透明带
  let gapStep = 0;    // 数据聚合步长(秒);相邻点间隔明显大于它 → 视为离线空档:断线+底纹
  const hidden = series.map(() => false); // 图例点击隐藏的序列(不参与绘制/量程)
  let hoverX = -1;
  const isGap = (i) => i > 0 && gapStep > 0 && ts[i] - ts[i - 1] > gapStep * 2.5;

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
      const item = el("span", "lg" + (hidden[i] ? " off" : ""));
      const sw = el("span", "sw");
      sw.style.background = cs[i];
      item.appendChild(sw);
      // 常驻当前值读数:不悬停也能直接看到"现在是多少"
      const arr = data[i] || [];
      let last = null;
      for (let k = arr.length - 1; k >= 0; k--) {
        if (arr[k] != null) { last = arr[k]; break; }
      }
      item.appendChild(el("span", null, s.label + (last == null ? "" : " · " + yFmt(last))));
      // 点击图例项:切换该序列显隐(多序列图里单独看某一条)
      if (series.length > 1) {
        item.style.cursor = "pointer";
        item.setAttribute("role", "button");
        item.setAttribute("aria-pressed", hidden[i] ? "true" : "false");
        item.title = hidden[i] ? "点击显示" : "点击隐藏";
        item.addEventListener("click", () => { hidden[i] = !hidden[i]; rebuildLegend(); draw(); });
      }
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
      data.forEach((arr, si) => { if (!hidden[si]) for (const v of arr) if (v != null && v > hi) hi = v; });
      // 峰值带的上缘也要纳入量程,否则带体会被裁掉(隐藏的序列不计)
      if (bands) bands.forEach((arr, si) => { if (arr && !hidden[si]) for (const v of arr) if (v != null && v > hi) hi = v; });
      // 阈值线也纳入量程,保证虚线在可见范围内
      for (const th of thresholds) if (th && th.value != null && th.value > hi) hi = th.value;
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
    // 告警阈值虚线:命中即将告警的水平参考线(仅当图表 y 单位与规则一致时由调用方传入)
    if (thresholds.length) {
      ctx.save();
      ctx.setLineDash([5, 4]);
      ctx.lineWidth = 1.2;
      const thCol = cssVar("--bad") || "#c96a5e";
      ctx.strokeStyle = thCol;
      ctx.fillStyle = thCol;
      ctx.textAlign = "left";
      for (const th of thresholds) {
        if (th == null || th.value == null) continue;
        const y = yOf(th.value);
        if (y < padT || y > padT + ih) continue;
        ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
        if (th.label) ctx.fillText(th.label, padL + 4, y - 3);
      }
      ctx.restore();
    }
    // X 时间刻度:对齐到"整"的时间边界(整点 / 整 5·15·30 分 / 整天),不再出现 13:07 这种怪刻度
    ctx.textAlign = "center";
    const dayScale = tr > 86400 * 2;
    const niceT = niceTimeStep(tr / Math.max(2, Math.floor(iw / 90)));
    const tzOff = new Date().getTimezoneOffset() * 60; // 秒;对齐到本地时区边界
    let lk = Math.ceil((t0 - tzOff) / niceT) * niceT; // 首个 >= t0 的本地整边界(本地秒)
    for (; lk + tzOff <= t1 + 1e-6; lk += niceT) {
      const t = lk + tzOff;
      if (t < t0) continue;
      const d = new Date(t * 1000);
      const label = dayScale
        ? (d.getMonth() + 1) + "/" + d.getDate()
        : String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
      ctx.fillText(label, xOf(t), H - 6);
    }

    // 离线/缺数空档:相邻点间隔明显大于聚合步长 → 淡色底纹标出(线在下方序列绘制处断开),
    // 不再用一条直线"假装"这段时间有数据。
    if (gapStep > 0) {
      ctx.fillStyle = mutedCol;
      ctx.globalAlpha = 0.07;
      for (let i = 1; i < ts.length; i++) {
        if (isGap(i)) {
          const x1 = xOf(ts[i - 1]), x2 = xOf(ts[i]);
          ctx.fillRect(x1, padT, x2 - x1, ih);
        }
      }
      ctx.globalAlpha = 1;
    }

    // 序列:按连续无 null 的"段"分别绘制(可平滑曲线/可选数据点,各段各自补面);
    // 空档处(isGap)同样断段。
    const cs = colors();
    series.forEach((s, si) => {
      if (hidden[si]) return; // 图例点击隐藏的序列不绘制
      const arr = data[si];
      // 峰值带:均值线与桶内峰值之间的半透明区域,让被 AVG 抹平的尖峰仍然可见
      const bd = bands && bands[si];
      if (bd) {
        const bruns = [];
        let bc = [];
        for (let i = 0; i < ts.length; i++) {
          const v = arr[i], m = bd[i];
          if (v == null || m == null || isGap(i)) {
            if (bc.length) bruns.push(bc);
            bc = [];
            if (v == null || m == null) continue;
          }
          bc.push({ x: xOf(ts[i]), ya: yOf(Math.min(v, hi)), ym: yOf(Math.min(m, hi)) });
        }
        if (bc.length) bruns.push(bc);
        ctx.fillStyle = cs[si];
        ctx.globalAlpha = 0.13;
        for (const run of bruns) {
          if (run.length < 2) continue;
          ctx.beginPath();
          ctx.moveTo(run[0].x, run[0].ym);
          for (let i = 1; i < run.length; i++) ctx.lineTo(run[i].x, run[i].ym);
          for (let i = run.length - 1; i >= 0; i--) ctx.lineTo(run[i].x, run[i].ya);
          ctx.closePath();
          ctx.fill();
        }
        ctx.globalAlpha = 1;
      }
      const runs = [];
      let cur = [];
      for (let i = 0; i < ts.length; i++) {
        const v = arr[i];
        if (isGap(i) && cur.length) { runs.push(cur); cur = []; }
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
          // 垂直渐变填充:近曲线处较实、向底部渐隐,比纯色平铺更有层次(五套主题通用)
          const grad = ctx.createLinearGradient(0, padT, 0, padT + ih);
          grad.addColorStop(0, withAlpha(cs[si], 0.26));
          grad.addColorStop(1, withAlpha(cs[si], 0.02));
          ctx.fillStyle = grad;
          ctx.fill();
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
        if (hidden[si]) return;
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
        if (hidden[si]) return; // 隐藏的序列不进提示
        const v = data[si][idx];
        // 有峰值带且该桶峰值高于均值时,提示里一并给出(尖峰的精确值)
        const m = bands && bands[si] ? bands[si][idx] : null;
        const peak = v != null && m != null && m > v ? "(峰 " + yFmt(m) + ")" : "";
        tip.appendChild(el("div", null, s.label + ": " + (v == null ? "-" : yFmt(v)) + peak));
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
  // 触屏取值:跟随手指显示十字线与数值(passive,不阻碍页面滚动);抬手后读数保留,
  // 便于看清。此前只有 mousemove,手机上完全无法取值。
  const touchAt = (e) => {
    const t = e.touches && e.touches[0];
    if (!t) return;
    const r = canvas.getBoundingClientRect();
    hoverX = t.clientX - r.left;
    draw();
  };
  canvas.addEventListener("touchstart", touchAt, { passive: true });
  canvas.addEventListener("touchmove", touchAt, { passive: true });

  const ro = new ResizeObserver(draw);
  ro.observe(container);
  // 命名主题监听器,便于 destroy() 时精确移除(否则每次重建图都会累积一个 document 级监听)。
  const onTheme = () => { rebuildLegend(); draw(); };
  document.addEventListener("op-theme", onTheme);

  const controller = {
    /* newBands:与 series 平行的峰值数组(可省略);newGapStep:聚合步长秒(可省略,
       供空档断线/底纹判定)。旧调用 setData(ts, data) 不受影响。 */
    setData(newTs, newData, newBands, newGapStep) {
      ts = newTs;
      data = newData;
      bands = newBands || null;
      gapStep = newGapStep || 0;
      rebuildLegend(); // 图例含当前值读数,随数据刷新
      draw();
    },
    append(t, values, maxPoints) {
      ts.push(t);
      values.forEach((v, i) => data[i] && data[i].push(v));
      // 实时点即瞬时值,峰=值:带宽收敛为 0,与历史段的峰值带自然衔接
      if (bands) values.forEach((v, i) => bands[i] && bands[i].push(v));
      const cap = maxPoints || 720;
      if (ts.length > cap) {
        ts.splice(0, ts.length - cap);
        data.forEach((a) => a.splice(0, a.length - cap));
        if (bands) bands.forEach((a) => a && a.splice(0, a.length - cap));
      }
      rebuildLegend();
      draw();
    },
    setThresholds(list) { thresholds = list || []; draw(); }, // 告警阈值虚线(异步取到规则后设置)
    draw, // 供全局展示选项切换时统一重绘
    /* 释放图表:断开 ResizeObserver、移除主题监听、从 ALL_CHARTS 摘除、清 DOM。
       反复重建图的页面(如对比页)必须在重建前调用,否则观察者/监听器/闭包会持续泄漏(F2)。 */
    destroy() {
      ro.disconnect();
      document.removeEventListener("op-theme", onTheme);
      const i = ALL_CHARTS.indexOf(controller);
      if (i >= 0) ALL_CHARTS.splice(i, 1);
      canvas.remove();
      tip.remove();
      legend.remove();
    },
  };
  ALL_CHARTS.push(controller);
  return controller;
}
