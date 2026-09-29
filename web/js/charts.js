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

// ---- диаграммы «x — y» для раздела ML: кривые качества, распределения, калибровка ----

const P = { l: 50, r: 14, t: 24, b: 34 };

function makeScale(min, max, log, from, to) {
  if (log) {
    const a = Math.log10(min), b = Math.log10(max);
    return (v) => from + ((Math.log10(Math.max(v, min)) - a) / (b - a)) * (to - from);
  }
  return (v) => from + ((v - min) / (max - min || 1)) * (to - from);
}

/**
 * Диаграмма «x — y». series: [{label, color, x:[], y:[], dash?, area?}]. Оси линейные или логарифмические.
 * vlines: [{x, label, color}] — вертикальные отметки (пороги, целевой FPR); marks: [{x, y, label, color}] — рабочие точки;
 * diagonal — линия y = x (идеальная калибровка).
 */
export function xy(series, { width = 520, height = 270, logX = false, logY = false, xMin, xMax, yMin = 0, yMax = 1,
  xTicks, yTicks, xFmt = (v) => fmt.num(v, 2), yFmt = (v) => fmt.num(v, 2), xLabel = '', yLabel = '', vlines = [], marks = [], diagonal = false } = {}) {
  const W = width, H = height;
  const xs = series.flatMap((s) => s.x);
  const x0 = xMin ?? Math.min(...xs), x1 = xMax ?? Math.max(...xs);
  const sx = makeScale(x0, x1, logX, P.l, W - P.r);
  const sy = makeScale(yMin, yMax, logY, H - P.b, P.t);
  const g = svg('g', { class: 'grid' });
  const labels = [];
  const yt = yTicks || [0, 0.25, 0.5, 0.75, 1].map((f) => yMin + (yMax - yMin) * f);
  for (const v of yt) {
    g.append(svg('line', { x1: P.l, x2: W - P.r, y1: sy(v), y2: sy(v) }));
    labels.push(svg('text', { x: P.l - 6, y: sy(v) + 3.5, 'text-anchor': 'end' }, yFmt(v)));
  }
  const xt = xTicks || [0, 0.25, 0.5, 0.75, 1].map((f) => x0 + (x1 - x0) * f);
  for (const v of xt) {
    g.append(svg('line', { x1: sx(v), x2: sx(v), y1: P.t, y2: H - P.b }));
    labels.push(svg('text', { x: sx(v), y: H - P.b + 15, 'text-anchor': 'middle' }, xFmt(v)));
  }
  if (xLabel) labels.push(svg('text', { x: (P.l + W - P.r) / 2, y: H - 3, 'text-anchor': 'middle' }, xLabel));
  if (yLabel) labels.push(svg('text', { x: 4, y: 11, 'text-anchor': 'start' }, yLabel));
  const els = [];
  if (diagonal) els.push(svg('line', { x1: sx(Math.max(x0, yMin)), y1: sy(Math.max(x0, yMin)), x2: sx(Math.min(x1, yMax)), y2: sy(Math.min(x1, yMax)), stroke: 'var(--muted)', 'stroke-dasharray': '4 4' }));
  for (const v of vlines) {
    els.push(svg('line', { x1: sx(v.x), x2: sx(v.x), y1: P.t, y2: H - P.b, stroke: v.color || 'var(--muted)', 'stroke-dasharray': '5 3', 'stroke-width': 1.2 }, svg('title', {}, v.label)));
  }
  for (const s of series) {
    const pts = s.x.map((x, i) => [sx(x), sy(s.y[i])]);
    const d = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
    if (s.area) els.push(svg('path', { d: `${d} L${pts[pts.length - 1][0].toFixed(1)} ${sy(yMin)} L${pts[0][0].toFixed(1)} ${sy(yMin)} Z`, fill: s.color, opacity: 0.12 }));
    els.push(svg('path', { d, fill: 'none', stroke: s.color, 'stroke-width': 1.9, 'stroke-linejoin': 'round', 'stroke-dasharray': s.dash || null }));
    if (s.dots) s.x.forEach((x, i) => els.push(svg('circle', { cx: sx(x), cy: sy(s.y[i]), r: 3.4, fill: s.color }, svg('title', {}, `${s.label}\n${xFmt(x)} → ${yFmt(s.y[i])}${s.n ? '\nвызовов: ' + fmt.int(s.n[i]) : ''}`))));
    else s.x.forEach((x, i) => els.push(svg('circle', { cx: sx(x), cy: sy(s.y[i]), r: 6, fill: 'transparent' }, svg('title', {}, `${s.label}\n${xLabel || 'x'}: ${xFmt(x)}\n${yLabel || 'y'}: ${yFmt(s.y[i])}`))));
  }
  for (const m of marks) {
    els.push(svg('circle', { cx: sx(m.x), cy: sy(m.y), r: 5.5, fill: m.color, stroke: 'var(--panel)', 'stroke-width': 2 }, svg('title', {}, m.label)));
  }
  const legend = [...series.map((s) => ({ label: s.label, color: s.color })), ...vlines.map((v) => ({ label: v.label, color: v.color || 'var(--muted)' })), ...marks.map((m) => ({ label: m.label, color: m.color }))];
  return chartBlock(svg('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, role: 'img' }, g, ...els, ...labels), legend);
}

/**
 * Гистограмма по границам корзин (лог-шкала по x). bars: [{label, color, values:[]}] — значения нормируются на сумму ряда,
 * чтобы малочисленный класс (мошенничество) не терялся рядом с массовым (легитимные).
 */
export function histogram(edges, bars, { width = 520, height = 270, vlines = [], xFmt = (v) => fmt.num(v, 3) } = {}) {
  const W = width, H = height;
  const n = edges.length - 1;
  const sx = makeScale(edges[0], edges[n], true, P.l, W - P.r);
  const norm = bars.map((b) => { const t = b.values.reduce((a, c) => a + c, 0) || 1; return b.values.map((v) => v / t); });
  const max = niceCeil(Math.max(...norm.flat(), 0.01));
  const sy = makeScale(0, max, false, H - P.b, P.t);
  const g = svg('g', { class: 'grid' });
  const labels = [];
  for (let i = 0; i <= 4; i++) {
    const v = (max * i) / 4;
    g.append(svg('line', { x1: P.l, x2: W - P.r, y1: sy(v), y2: sy(v) }));
    labels.push(svg('text', { x: P.l - 6, y: sy(v) + 3.5, 'text-anchor': 'end' }, fmt.pct(v, 0)));
  }
  for (const v of [1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1]) labels.push(svg('text', { x: sx(v), y: H - P.b + 15, 'text-anchor': 'middle' }, xFmt(v)));
  labels.push(svg('text', { x: (P.l + W - P.r) / 2, y: H - 3, 'text-anchor': 'middle' }, 'score модели (риск), логарифмическая шкала'));
  const els = [];
  bars.forEach((b, k) => {
    for (let i = 0; i < n; i++) {
      const v = norm[k][i];
      if (!v) continue;
      const x = sx(edges[i]), w = Math.max(1, sx(edges[i + 1]) - sx(edges[i]) - 1);
      els.push(svg('rect', { x, y: sy(v), width: w, height: sy(0) - sy(v), fill: b.color, opacity: 0.55 },
        svg('title', {}, `${b.label}\nscore ${xFmt(edges[i])}–${xFmt(edges[i + 1])}\nдоля класса: ${fmt.pct(v, 1)}\nвызовов: ${fmt.int(b.values[i])}`)));
    }
  });
  for (const v of vlines) els.push(svg('line', { x1: sx(v.x), x2: sx(v.x), y1: P.t, y2: H - P.b, stroke: v.color, 'stroke-dasharray': '5 3', 'stroke-width': 1.6 }, svg('title', {}, v.label)));
  const legend = [...bars.map((b) => ({ label: b.label, color: b.color })), ...vlines.map((v) => ({ label: v.label, color: v.color }))];
  return chartBlock(svg('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, role: 'img' }, g, ...els, ...labels), legend);
}
