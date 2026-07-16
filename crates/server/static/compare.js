/* 多节点对比:勾选节点,叠加 CPU / 内存曲线。桶时间戳按同一 step 对齐后合并。 */
"use strict";

const COLORS = ["--chart1", "--chart2", "--chart3", "--chart4"];
let NODES = [];
let selected = new Set();
let curSecs = 3600;
let cpuChart = null, memChart = null;

async function loadNodes() {
  const d = await api("GET", "/api/nodes");
  NODES = (d.nodes || []).filter((n) => n.registered);
  const box = $("#nodePick");
  box.replaceChildren();
  for (const n of NODES) {
    const lab = el("label", "pick-item");
    const cb = el("input"); cb.type = "checkbox"; cb.value = String(n.id);
    cb.addEventListener("change", () => {
      if (cb.checked) {
        if (selected.size >= 8) { cb.checked = false; alert("最多对比 8 个节点"); return; }
        selected.add(n.id);
      } else selected.delete(n.id);
      redraw();
    });
    lab.appendChild(cb);
    const nameSpan = el("span", null, " " + n.name);
    nameSpan.title = n.name;
    lab.appendChild(nameSpan);
    box.appendChild(lab);
  }
}

async function redraw() {
  const ids = Array.from(selected);
  const series = ids.map((id, i) => {
    const n = NODES.find((x) => x.id === id);
    return { label: (n ? n.name : "#" + id), colorVar: COLORS[i % COLORS.length] };
  });
  // 重新构造图(series 数量变化):先销毁旧图,释放其 ResizeObserver / 主题监听 / 全局引用,
  // 否则每次勾选或切换时间范围都会泄漏一份(F2)。destroy() 已清理旧 canvas/tip/legend。
  if (cpuChart) { cpuChart.destroy(); cpuChart = null; }
  if (memChart) { memChart.destroy(); memChart = null; }
  $("#cpuChart").replaceChildren();
  $("#memChart").replaceChildren();
  document.querySelectorAll(".chart-legend").forEach((n) => n.remove());
  cpuChart = opChart($("#cpuChart"), { series, yFmt: (v) => v.toFixed(0) + "%", yMax: 100 });
  memChart = opChart($("#memChart"), { series, yFmt: (v) => v.toFixed(0) + "%", yMax: 100 });
  if (!ids.length) { cpuChart.setData([], []); memChart.setData([], []); return; }

  // 拉取各节点历史
  const datas = await Promise.all(ids.map((id) =>
    api("GET", "/api/nodes/" + id + "/metrics?secs=" + curSecs).catch(() => ({ points: [] }))));
  // 合并时间轴(同 step → 桶对齐)
  const tsSet = new Set();
  const maps = datas.map((d) => {
    const cpu = new Map(), mem = new Map();
    for (const p of d.points) {
      tsSet.add(p[0]);
      cpu.set(p[0], p[1]);
      mem.set(p[0], p[3] > 0 ? (p[2] / p[3] * 100) : 0);
    }
    return { cpu, mem };
  });
  const ts = Array.from(tsSet).sort((a, b) => a - b);
  const cpuData = maps.map((m) => ts.map((t) => (m.cpu.has(t) ? m.cpu.get(t) : null)));
  const memData = maps.map((m) => ts.map((t) => (m.mem.has(t) ? m.mem.get(t) : null)));
  // 全部节点同时缺数的窗口(如服务端停机)靠 gapStep 断线;单节点缺数已由 null 对齐处理
  const step = (datas.find((x) => x && x.step) || {}).step || 0;
  cpuChart.setData(ts, cpuData, null, step);
  memChart.setData(ts, memData, null, step);
}

document.addEventListener("DOMContentLoaded", async () => {
  try { await loadNodes(); } catch (_) {}
  redraw();
  $("#rangeSeg").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-secs]");
    if (!b) return;
    $$("#rangeSeg button").forEach((x) => x.classList.toggle("active", x === b));
    curSecs = parseInt(b.dataset.secs, 10);
    redraw();
  });
});
