// «Граф связей» — все четыре графовых детектора движка: веера (группы с общим шаблоном и
// непересекающимися списками адресатов), цепочки переадресации, SIM-box (только исходящие,
// новый собеседник раз за разом) и карусели (закрытая группа звонит только друг другу).
// Слева у веера и карусели — список групп, справа — разбор выбранной; цепочки и SIM-box —
// табличные списки без выбора (у них нет «состава», который имело бы смысл разворачивать).

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
    fanSection(fans.groups || [], ctx),
    h('div', { style: 'margin-top:14px' }, chainSection(chains.chains || [])),
    h('div', { class: 'grid cols-2', style: 'margin-top:14px' },
      simboxSection(simbox.members || []),
      carouselSection(carousel.groups || [])),
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

  const list = h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Группа'), h('th', { class: 'num' }, 'Номеров'), h('th', { class: 'num' }, 'Вызовов'), h('th', { class: 'num' }, 'Непересечение'))),
    h('tbody', {}, groups.map((g) => h('tr', {
      class: 'row', style: g.id === selected.id ? 'background:var(--panel-head)' : '',
      onclick: () => { ctx.fanSelected = g.id; ctx.rerender(); },
    },
    h('td', { class: 'mono', style: 'white-space:nowrap' }, g.label), h('td', { class: 'num' }, fmt.int(g.size)), h('td', { class: 'num' }, fmt.int(g.calls)), h('td', { class: 'num' }, fmt.pct(g.disjoint, 0)))))));

  return h('div', { class: 'grid cols-3' },
    widget('Веера номеров', list, { sub: plural(groups.length, 'группа', 'группы', 'групп'), flush: true }),
    widget(`Веер ${selected.label}`, fanGraph(selected), { sub: `${selected.size} номеров · непересечение списков ${fmt.pct(selected.disjoint, 0)}`, cls: 'span-2' }));
}

/** Двудольный граф: слева звонящие, справа образец их адресатов. Общих адресатов у веера почти нет — рёбра не пересекаются. */
function fanGraph(g) {
  const members = g.members.slice(0, 16);
  const W = 720;
  const rowH = 30;
  const H = Math.max(140, members.length * rowH + 30);
  const xL = 130;
  const xR = 560;
  const els = [];
  members.forEach((m, i) => {
    const y = 24 + i * rowH;
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
    svg('svg', { class: 'graph', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Граф веера' }, ...els),
    h('div', { class: 'graph-legend' },
      h('span', {}, h('i', { class: 'dot', style: 'background:var(--c-block);margin-right:6px' }), 'номера веера'),
      h('span', {}, h('i', { class: 'dot', style: 'background:var(--c-info);margin-right:6px' }), 'адресаты (образец)'),
      g.members.length > members.length ? h('span', {}, `показаны 16 из ${g.members.length}`) : null),
    );
}

// ---- цепочки переадресации ----

function chainSection(chains) {
  if (!chains.length) {
    return widget('Цепочки переадресации', emptyHint(
      'Записи типа «переадресация», где цель сама переадресует дальше (B → C → D), от трёх узлов. '
      + 'Горячая линия на несколько номеров компании (одна и та же цель у многих источников) сюда не '
      + 'попадает — это легальный узел сбора, не звено цепочки.'));
  }
  const rows = chains.map((c) => h('div', { class: 'chain-row' },
    c.nodes.map((n, i) => [i > 0 ? chainArrow() : null, h('span', { class: 'mono chain-node' }, n)]),
    c.ring ? h('span', { class: 'chip hot', style: 'margin-left:10px' }, 'кольцо') : null));
  return widget('Цепочки переадресации', h('div', { class: 'chain-list' }, rows),
    { sub: plural(chains.length, 'цепочка', 'цепочки', 'цепочек') });
}

function chainArrow() {
  return svg('svg', { width: 22, height: 14, viewBox: '0 0 22 14', style: 'flex:none;margin:0 4px;vertical-align:-3px' },
    svg('path', { d: 'M1 7 H17', stroke: 'var(--on-surface-variant)', 'stroke-width': 1.6, fill: 'none' }),
    svg('path', { d: 'M12 2 L18 7 L12 12', stroke: 'var(--on-surface-variant)', 'stroke-width': 1.6, fill: 'none', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));
}

// ---- SIM-box ----

function simboxSection(members) {
  if (!members.length) {
    return widget('SIM-box', emptyHint(
      'Несколько SIM работают только на исходящие, каждый получатель — новый, длительность обычная '
      + '(короткие вызовы — это уже веер/wangiri, не SIM-box). Номер с хоть одним входящим сюда не '
      + 'попадает — вероятный колл-центр.'));
  }
  const rows = h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Номер'), h('th', { class: 'num' }, 'Вызовов'), h('th', { class: 'num' }, 'Собеседников'))),
    h('tbody', {}, members.slice(0, 50).map((m) => h('tr', {},
      h('td', { class: 'mono' }, m.number), h('td', { class: 'num' }, fmt.int(m.calls)), h('td', { class: 'num' }, fmt.int(m.peers)))))));
  return widget('SIM-box', rows, { sub: plural(members.length, 'номер', 'номера', 'номеров'), flush: true });
}

// ---- карусели ----

function carouselSection(groups) {
  if (!groups.length) {
    return widget('Карусели', emptyHint(
      'Закрытая группа из нескольких номеров звонит только друг другу: мало уникальных собеседников '
      + 'за весь период при заметном объёме вызовов, контактов за пределами группы почти нет.'));
  }
  const body = groups.map((g) => h('div', { class: 'carousel-group' },
    h('div', { class: 'muted', style: 'font-size:12px;margin-bottom:6px' }, `${plural(g.members.length, 'номер', 'номера', 'номеров')} в группе`),
    h('div', {}, g.members.map((n) => h('span', { class: 'chip' }, n)))));
  return widget('Карусели', h('div', {}, body), { sub: plural(groups.length, 'группа', 'группы', 'групп') });
}

function emptyHint(text) {
  return h('div', { class: 'empty hint' }, text);
}
