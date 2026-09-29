// Небольшая библиотека SVG-диаграмм (без внешних зависимостей: панель работает в закрытом контуре).

import { h, svg, fmt } from './ui.js';

const M = { l: 52, r: 8, t: 8, b: 22 };

/** «Красивый» верх шкалы: 1, 2, 5 × 10^k. */
export function niceCeil(v) {
  if (!(v > 0)) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}

function frame(W, height, max, yFmt) {
  const ih = height - M.t - M.b;
  const g = svg('g', { class: 'grid' });
  const labels = [];
  for (let i = 0; i <= 4; i++) {
    const y = M.t + ih - (ih * i) / 4;
    g.append(svg('line', { x1: M.l, x2: W - M.r, y1: y, y2: y }));
    labels.push(svg('text', { x: M.l - 6, y: y + 3.5, 'text-anchor': 'end' }, yFmt((max * i) / 4)));
  }
  return { ih, g, labels };
}

function xAxis(W, points, height, n) {
  const iw = W - M.l - M.r;
  const out = [];
  const ticks = Math.min(W < 500 ? 3 : 6, points.length);
  for (let i = 0; i < ticks; i++) {
    const idx = Math.round((i * (points.length - 1)) / Math.max(1, ticks - 1));
    const x = M.l + (iw * (idx + 0.5)) / n;
    out.push(svg('text', { x, y: height - 6, 'text-anchor': i === 0 ? 'start' : i === ticks - 1 ? 'end' : 'middle' }, fmt.time(points[idx].t * 1000)));
  }
  return out;
}

/** Столбчатая диаграмма с накоплением. series: [{key, color, label}] снизу вверх. */
export function stackedBars(points, series, { width = 720, height = 220, yFmt = (v) => fmt.int(v) } = {}) {
  const W = width;
  const n = points.length;
  const totals = points.map((p) => series.reduce((s, x) => s + (p[x.key] || 0), 0));
  const max = niceCeil(Math.max(...totals, 1));
  const { ih, g, labels } = frame(W, height, max, yFmt);
  const iw = W - M.l - M.r;
  const bw = Math.max(1, (iw / Math.max(n, 1)) * 0.78);
  const bars = svg('g');
  points.forEach((p, i) => {
    let y = M.t + ih;
    const x = M.l + (iw * i) / n + (iw / n - bw) / 2;
    const tip = `${fmt.time(p.t * 1000)}\n` + series.map((s) => `${s.label}: ${fmt.int(p[s.key] || 0)}`).join('\n');
    const col = svg('g', {}, svg('title', {}, tip));
    for (const s of series) {
      const v = p[s.key] || 0;
      if (!v) continue;
      const hgt = (v / max) * ih;
      y -= hgt;
      col.append(svg('rect', { x, y, width: bw, height: Math.max(0.5, hgt), fill: s.color, rx: 1 }));
    }
    bars.append(col);
  });
  return chartBlock(svg('svg', { class: 'chart', viewBox: `0 0 ${W} ${height}`, role: 'img' }, g, bars, ...labels, ...xAxis(W, points, height, n)), series);
}

/** Линейная диаграмма нескольких рядов. */
export function lines(points, series, { width = 720, height = 220, yFmt = (v) => fmt.num(v, 0), min = 0 } = {}) {
  const W = width;
  const n = points.length;
  const vals = points.flatMap((p) => series.map((s) => p[s.key] || 0));
  const max = niceCeil(Math.max(...vals, 1));
  const { ih, g, labels } = frame(W, height, max, yFmt);
  const iw = W - M.l - M.r;
  const at = (i, v) => [M.l + (iw * (i + 0.5)) / Math.max(n, 1), M.t + ih - ((v - min) / (max - min || 1)) * ih];
  const paths = series.map((s) => {
    const d = points.map((p, i) => at(i, p[s.key] || 0)).map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
    return svg('path', { d, fill: 'none', stroke: s.color, 'stroke-width': 1.8, 'stroke-linejoin': 'round' });
  });
  const hover = points.map((p, i) => {
    const [x] = at(i, 0);
    const tip = `${fmt.time(p.t * 1000)}\n` + series.map((s) => `${s.label}: ${yFmt(p[s.key] || 0)}`).join('\n');
    return svg('rect', { x: x - iw / n / 2, y: M.t, width: iw / n, height: ih, fill: 'transparent' }, svg('title', {}, tip));
  });
  return chartBlock(svg('svg', { class: 'chart', viewBox: `0 0 ${W} ${height}`, role: 'img' }, g, ...paths, ...hover, ...labels, ...xAxis(W, points, height, n)), series);
}

function chartBlock(chart, series) {
  return h('div', {}, chart,
    h('div', { class: 'legend' }, series.map((s) => h('span', {}, h('i', { style: `background:${s.color}` }), s.label))));
}

/** Небольшой кольцевой индикатор доли (0..1). */
export function ring(value, { size = 92, color = 'var(--accent)', label = '' } = {}) {
  const r = 36;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(1, value || 0));
  return h('div', { style: 'display:grid;place-items:center' },
    svg('svg', { viewBox: '0 0 100 100', width: size, height: size },
      svg('circle', { cx: 50, cy: 50, r, fill: 'none', stroke: 'var(--line)', 'stroke-width': 10 }),
      svg('circle', { cx: 50, cy: 50, r, fill: 'none', stroke: color, 'stroke-width': 10, 'stroke-dasharray': `${(c * v).toFixed(1)} ${c.toFixed(1)}`, 'stroke-linecap': 'round', transform: 'rotate(-90 50 50)' }),
      svg('text', { x: 50, y: 55, 'text-anchor': 'middle', style: 'font-size:15px;font-weight:600;fill:var(--text)' }, Math.round(v * 100) + '%')),
    label ? h('div', { class: 'muted', style: 'font-size:12px' }, label) : null);
}
