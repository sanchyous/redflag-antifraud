// «Граф связей» — все четыре графовых детектора движка показаны как действительно граф (узлы и
// рёбра), а не список: веер — двудольный граф (звонящие слева, образец адресатов справа), карусель —
// замкнутая группа по кругу (все со всеми), SIM-box — звезда расходящихся одноразовых контактов на
// каждый номер, цепочка переадресации — направленная линия узлов (кольцо замыкается дугой).

import { getCarousel, getChains, getFans, getSimBox } from '../api.js';
import { fmt, h, svg, widget } from '../ui.js';

/** Склонение числительных: 1 группа, 2 группы, 5 групп. */
function plural(n, one, few, many) {
  const m10 = n % 10;
  const m100 = n % 100;
  const word = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
  return `${n} ${word}`;
}

export async function render(root, ctx) {
  const [fans, chains, simbox, carousel] = await Promise.all([
    getFans().catch(() => ({ groups: [] })),
    getChains().catch(() => ({ chains: [] })),
    getSimBox().catch(() => ({ members: [] })),
    getCarousel().catch(() => ({ groups: [] })),
  ]);
  root.replaceChildren(
    h('div', { class: 'grid cols-2' },
      fanSection(fans.groups || [], ctx),
      carouselSection(carousel.groups || [], ctx)),
    h('div', { class: 'grid cols-2', style: 'margin-top:14px' },
      chainSection(chains.chains || []),
      simboxSection(simbox.members || [])),
  );
}

// ---- веера ----

function fanSection(groups, ctx) {
  if (!groups.length) {
    return widget('Веера номеров', emptyHint(
      'Группа номеров с общим шаблоном поведения (ритм, длительность, доля неотвеченных) и '
      + 'почти непересекающимися списками адресатов — обычные люди тоже звонят по шаблону, но колл-центр '
      + 'с общим пулом клиентов отличает пересечение списков.'));
  }
  const selected = groups.find((g) => g.id === ctx.fanSelected) || groups[0];
  ctx.fanSelected = selected.id;

  const chips = h('div', { class: 'graph-picker' }, groups.map((g) => h('button', {
    class: 'chip picker' + (g.id === selected.id ? ' active' : ''),
    onclick: () => { ctx.fanSelected = g.id; ctx.rerender(); },
  }, g.label)));

  return widget('Веера номеров',
    h('div', {}, chips, fanGraph(selected)),
    { sub: plural(groups.length, 'группа', 'группы', 'групп') + ` · ${selected.size} номеров · непересечение ${fmt.pct(selected.disjoint, 0)}` });
}

/** Двудольный граф: слева звонящие, справа образец их адресатов. Общих адресатов у веера почти нет — рёбра не пересекаются. */
function fanGraph(g) {
  const members = g.members.slice(0, 16);
  const W = 640;
  const rowH = 28;
  const H = Math.max(140, members.length * rowH + 30);
  const xL = 120;
  const xR = 500;
  const els = [];
  members.forEach((m, i) => {
    const y = 22 + i * rowH;
    const peers = (m.peers || []).slice(0, 3);
    peers.forEach((p, j) => {
      const py = y + (j - (peers.length - 1) / 2) * 8;
      els.push(svg('line', { x1: xL + 6, y1: y, x2: xR - 6, y2: py, stroke: 'var(--c-info)', 'stroke-opacity': 0.4, 'stroke-width': 1 }));
      els.push(svg('circle', { cx: xR, cy: py, r: 3.2, fill: 'var(--c-info)' }));
      if (j === 0) els.push(svg('text', { x: xR + 10, y: py + 3 }, p));
    });
    els.push(svg('circle', { cx: xL, cy: y, r: 6, fill: 'var(--c-block)' }, svg('title', {}, `${m.number}: ${m.calls} вызовов, ${m.peer_count} разных адресатов`)));
    els.push(svg('text', { x: xL - 12, y: y + 3.5, 'text-anchor': 'end', style: 'font-size:11px;fill:var(--text)' }, m.number));
    els.push(svg('text', { x: xL + 12, y: y - 6 }, `${m.peer_count} адр.`));
  });
  return h('div', {},
    svg('svg', { class: 'graph', viewBox: `0 0 ${W} ${H}` }, ...els),
    h('div', { class: 'graph-legend' },
      h('span', {}, h('i', { class: 'dot', style: 'background:var(--c-block);margin-right:6px' }), 'номера веера'),
      h('span', {}, h('i', { class: 'dot', style: 'background:var(--c-info);margin-right:6px' }), 'адресаты (образец)'),
      g.members.length > members.length ? h('span', {}, `показаны 16 из ${g.members.length}`) : null));
}

// ---- карусели: замкнутая группа по кругу, рёбра — все со всеми (это и есть определение карусели) ----

function carouselSection(groups, ctx) {
  if (!groups.length) {
    return widget('Карусели', emptyHint(
      'Закрытая группа из нескольких номеров звонит только друг другу: мало уникальных собеседников '
      + 'за весь период при заметном объёме вызовов, контактов за пределами группы почти нет.'));
  }
  const selected = groups.find((g) => g.id === ctx.carouselSelected) || groups[0];
  ctx.carouselSelected = selected.id;

  const chips = h('div', { class: 'graph-picker' }, groups.map((g) => h('button', {
    class: 'chip picker' + (g.id === selected.id ? ' active' : ''),
    onclick: () => { ctx.carouselSelected = g.id; ctx.rerender(); },
  }, `группа · ${g.members.length}`)));

  return widget('Карусели',
    h('div', {}, chips, carouselGraph(selected.members)),
    { sub: plural(groups.length, 'группа', 'группы', 'групп') });
}

function carouselGraph(members) {
  const n = Math.min(members.length, 14);
  const shown = members.slice(0, n);
  const W = 580;
  const H = 580;
  const cx = W / 2;
  const cy = H / 2;
  const R = 150;
  const pos = shown.map((_, i) => {
    const a = (2 * Math.PI * i) / n - Math.PI / 2;
    return [cx + R * Math.cos(a), cy + R * Math.sin(a)];
  });
  const els = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      els.push(svg('line', { x1: pos[i][0], y1: pos[i][1], x2: pos[j][0], y2: pos[j][1], stroke: 'var(--c-review)', 'stroke-opacity': 0.22, 'stroke-width': 1 }));
    }
  }
  shown.forEach((m, i) => {
    const [x, y] = pos[i];
    const a = (2 * Math.PI * i) / n - Math.PI / 2;
    const lx = cx + (R + 26) * Math.cos(a);
    const ly = cy + (R + 26) * Math.sin(a);
    const anchor = Math.cos(a) > 0.3 ? 'start' : Math.cos(a) < -0.3 ? 'end' : 'middle';
    els.push(svg('circle', { cx: x, cy: y, r: 8, fill: 'var(--c-review)' }, svg('title', {}, m)));
    els.push(svg('text', { x: lx, y: ly + 3.5, 'text-anchor': anchor, style: 'font-size:10.5px;fill:var(--text)' }, m));
  });
  return h('div', {},
    svg('svg', { class: 'graph', viewBox: `0 0 ${W} ${H}` }, ...els),
    members.length > n ? h('div', { class: 'graph-legend' }, h('span', {}, `показаны 14 из ${members.length}`)) : null);
}

// ---- цепочки переадресации: направленная линия узлов, кольцо — дуга возврата ----

function chainSection(chains) {
  if (!chains.length) {
    return widget('Цепочки переадресации', emptyHint(
      'Записи типа «переадресация», где цель сама переадресует дальше (B → C → D), от трёх узлов. '
      + 'Горячая линия на несколько номеров компании (одна и та же цель у многих источников) сюда не '
      + 'попадает — это легальный узел сбора, не звено цепочки.'));
  }
  const rows = chains.slice(0, 12).map((c) => chainGraph(c));
  return widget('Цепочки переадресации', h('div', { class: 'chain-graphs' }, rows),
    { sub: plural(chains.length, 'цепочка', 'цепочки', 'цепочек') + (chains.length > 12 ? ` · показаны 12` : '') });
}

function chainGraph(c) {
  const n = c.nodes.length;
  const step = 90;
  const margin = 55;
  const W = margin + (n - 1) * step + margin;
  const H = 54;
  const y = 20;
  const els = [];
  c.nodes.forEach((node, i) => {
    const x = margin + i * step;
    if (i > 0) {
      const x0 = margin + (i - 1) * step + 9;
      const x1 = x - 9;
      els.push(svg('line', { x1: x0, y1: y, x2: x1, y2: y, stroke: 'var(--on-surface-variant)', 'stroke-width': 1.5 }));
      els.push(svg('path', { d: `M ${x1 - 5} ${y - 4} L ${x1} ${y} L ${x1 - 5} ${y + 4}`, stroke: 'var(--on-surface-variant)', 'stroke-width': 1.5, fill: 'none', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));
    }
    const color = i === 0 ? 'var(--c-block)' : i === n - 1 ? 'var(--c-review)' : 'var(--on-surface-variant)';
    els.push(svg('circle', { cx: x, cy: y, r: 8, fill: color }, svg('title', {}, node)));
    els.push(svg('text', { x, y: y + 24, 'text-anchor': 'middle', style: 'font-size:10.5px;fill:var(--text)' }, node));
  });
  if (c.ring) {
    const x0 = margin;
    const x1 = margin + (n - 1) * step;
    els.push(svg('path', { d: `M ${x1} ${y + 9} Q ${(x0 + x1) / 2} ${y + 40} ${x0} ${y + 9}`, stroke: 'var(--c-block)', fill: 'none', 'stroke-width': 1.4, 'stroke-dasharray': '3,2' }));
  }
  return h('div', { class: 'chain-graph-row' },
    svg('svg', { class: 'graph', width: W, height: H + 14, viewBox: `0 0 ${W} ${H + 14}` }, ...els),
    c.ring ? h('span', { class: 'chip hot' }, 'кольцо') : null);
}

// ---- SIM-box: звезда расходящихся одноразовых контактов — плотность лучей и есть улика ----

function simboxSection(members) {
  if (!members.length) {
    return widget('SIM-box', emptyHint(
      'Несколько SIM работают только на исходящие, каждый получатель — новый, длительность обычная '
      + '(короткие вызовы — это уже веер/wangiri, не SIM-box). Номер с хоть одним входящим сюда не '
      + 'попадает — вероятный колл-центр.'));
  }
  const cards = members.slice(0, 12).map((m) => h('div', { class: 'simbox-card' },
    simboxBurst(m),
    h('div', { class: 'mono', style: 'font-size:12px;margin-top:4px' }, m.number),
    h('div', { class: 'muted', style: 'font-size:11px' }, `${fmt.int(m.calls)} вызовов · ${fmt.int(m.peers)} адресатов, все разные`)));
  return widget('SIM-box', h('div', { class: 'simbox-grid' }, cards),
    { sub: plural(members.length, 'номер', 'номера', 'номеров') + (members.length > 12 ? ` · показаны 12 самых активных` : '') });
}

function simboxBurst(m) {
  const n = Math.min(m.peers, 24);
  const W = 120;
  const H = 120;
  const cx = W / 2;
  const cy = H / 2;
  const R = 46;
  const els = [];
  for (let i = 0; i < n; i++) {
    const a = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
    const x = cx + R * Math.cos(a);
    const y = cy + R * Math.sin(a);
    els.push(svg('line', { x1: cx, y1: cy, x2: x, y2: y, stroke: 'var(--c-block)', 'stroke-opacity': 0.3, 'stroke-width': 1 }));
    els.push(svg('circle', { cx: x, cy: y, r: 2, fill: 'var(--c-block)', 'fill-opacity': 0.7 }));
  }
  els.push(svg('circle', { cx, cy, r: 7, fill: 'var(--c-block)' }));
  return svg('svg', { class: 'graph', width: W, height: H, viewBox: `0 0 ${W} ${H}` }, ...els);
}

function emptyHint(text) {
  return h('div', { class: 'empty hint' }, text);
}
