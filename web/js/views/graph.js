// «Граф связей» — найденные «веера»: группы номеров с общим шаблоном поведения и непересекающимися списками
// адресатов. Слева — список групп, справа — двудольный граф выбранной группы (звонящие → образец их адресатов).

import { getFans } from '../api.js';
import { fmt, h, svg, widget } from '../ui.js';

/** Склонение числительных: 1 группа, 2 группы, 5 групп. */
function plural(n, one, few, many) {
  const m10 = n % 10;
  const m100 = n % 100;
  const word = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
  return `${n} ${word}`;
}

export async function render(root, ctx) {
  const data = await getFans();
  const groups = data.groups || [];
  if (!groups.length) {
    root.replaceChildren(widget('Веера номеров', h('div', { class: 'empty' },
      'Вееров не найдено')));
    return;
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

  root.replaceChildren(h('div', { class: 'grid cols-3' },
    widget('Найденные веера', list, { sub: plural(groups.length, 'группа', 'группы', 'групп'), flush: true }),
    widget(`Веер ${selected.label}`, fanGraph(selected), { sub: `${selected.size} номеров · непересечение списков ${fmt.pct(selected.disjoint, 0)}`, cls: 'span-2' })));
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
      els.push(svg('line', { x1: xL + 6, y1: y, x2: xR - 6, y2: py, stroke: 'var(--s2)', 'stroke-opacity': 0.4, 'stroke-width': 1 }));
      els.push(svg('circle', { cx: xR, cy: py, r: 3.2, fill: 'var(--s2)' }));
      if (j === 0) els.push(svg('text', { x: xR + 10, y: py + 3 }, p));
    });
    els.push(svg('circle', { cx: xL, cy: y, r: 6, fill: 'var(--red)' }, svg('title', {}, `${m.number}: ${m.calls} вызовов, ${m.peer_count} разных адресатов`)));
    els.push(svg('text', { x: xL - 12, y: y + 3.5, 'text-anchor': 'end', style: 'font-size:11px;fill:var(--text)' }, m.number));
    els.push(svg('text', { x: xL + 12, y: y - 6 }, `${m.peer_count} адр.`));
  });
  return h('div', {},
    svg('svg', { class: 'graph', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Граф веера' }, ...els),
    h('div', { class: 'graph-legend' },
      h('span', {}, h('i', { class: 'dot', style: 'background:var(--red);margin-right:6px' }), 'номера веера'),
      h('span', {}, h('i', { class: 'dot', style: 'background:var(--s2);margin-right:6px' }), 'адресаты (образец)'),
      g.members.length > members.length ? h('span', {}, `показаны 16 из ${g.members.length}`) : null),
    );
}
