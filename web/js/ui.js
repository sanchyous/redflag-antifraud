// Общие помощники интерфейса. Весь DOM строится через h() и textContent — данные из API никогда не попадают
// в разметку как HTML (защита от внедрения через маскированные номера, тексты причин и т.п.).

import { icon } from './icons.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

/** h('div', {class: 'a', onclick: fn}, 'текст', node, [ещё узлы]) → Element */
export function h(tag, attrs, ...children) {
  const el = tag.startsWith('svg:') ? document.createElementNS(SVG_NS, tag.slice(4)) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.setAttribute('class', v);
    else if (k === 'text') el.textContent = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export const svg = (tag, attrs, ...children) => h('svg:' + tag, attrs, ...children);

// ---- форматирование ----

const nf = new Intl.NumberFormat('ru-RU');

export const fmt = {
  int: (n) => (n === undefined || n === null || Number.isNaN(n) ? '—' : nf.format(Math.round(n))),
  num: (n, d = 1) => (n === undefined || n === null || Number.isNaN(n) ? '—' : n.toLocaleString('ru-RU', { maximumFractionDigits: d, minimumFractionDigits: 0 })),
  pct: (x, d = 1) => (Number.isFinite(x) ? (x * 100).toLocaleString('ru-RU', { maximumFractionDigits: d, minimumFractionDigits: 0 }) + ' %' : '—'),
  /** микросекунды → «850 мкс» / «12,4 мс» / «1,2 с» */
  us: (us) => {
    if (!Number.isFinite(us) || us <= 0) return '—';
    if (us < 1000) return Math.round(us) + ' мкс';
    if (us < 1e6) return (us / 1000).toLocaleString('ru-RU', { maximumFractionDigits: 1 }) + ' мс';
    return (us / 1e6).toLocaleString('ru-RU', { maximumFractionDigits: 2 }) + ' с';
  },
  time: (t) => new Date(t).toLocaleTimeString('ru-RU'),
  dateTime: (t) => new Date(t).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  uptime: (sec) => {
    if (!Number.isFinite(sec)) return '—';
    const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    return d ? `${d} д ${hh} ч` : hh ? `${hh} ч ${m} мин` : m ? `${m} мин` : `${Math.floor(sec)} с`;
  },
  signed: (n, d = 2) => (n > 0 ? '+' : n < 0 ? '−' : '') + Math.abs(n).toLocaleString('ru-RU', { maximumFractionDigits: d, minimumFractionDigits: d }),
  ago: (t) => {
    const s = (Date.now() - new Date(t).getTime()) / 1000;
    if (s < 5) return 'только что';
    if (s < 60) return Math.floor(s) + ' с назад';
    if (s < 3600) return Math.floor(s / 60) + ' мин назад';
    if (s < 86400) return Math.floor(s / 3600) + ' ч назад';
    return Math.floor(s / 86400) + ' д назад';
  },
};

export const DECISION_RU = { allow: 'Пропуск', review: 'Проверка', block: 'Блок' };

// ---- уведомления и боковая панель ----

let toastTimer;
export function toast(message, bad = false) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = 'toast' + (bad ? ' bad' : '');
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3500);
}

export function openDrawer(title, node) {
  const d = document.getElementById('drawer');
  d.replaceChildren(
    h('header', {}, h('span', {}, title), h('button', { class: 'icon-btn x', onclick: closeDrawer, 'aria-label': 'Закрыть' }, icon('close'))),
    h('div', { class: 'body' }, node),
  );
  d.hidden = false;
}

export function closeDrawer() {
  document.getElementById('drawer').hidden = true;
}

document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });

/** Виджет в стиле Zabbix: заголовок + тело. */
export function widget(title, body, { sub, cls = '', flush = false } = {}) {
  return h('section', { class: 'widget ' + cls },
    h('header', {}, title, sub ? h('span', { class: 'sub' }, sub) : null),
    h('div', { class: 'body' + (flush ? ' flush' : '') }, body));
}

/** Плитка показателя. tone: ok | warn | avg | high | info | '' */
export function tile(label, value, hint, tone = '') {
  return h('div', { class: 'tile ' + tone }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'hint' }, hint || ' '));
}

export function sevBadge(decision) {
  return h('span', { class: 'sev ' + decision }, DECISION_RU[decision] || decision);
}

/** Горизонтальные столбики «имя — значение». */
export function hbars(items, { color = 'var(--accent)', max, valWidth } = {}) {
  if (!items || !items.length) return h('div', { class: 'empty' }, 'Данных пока нет');
  const top = max ?? Math.max(...items.map((i) => i.value), 1);
  const cols = valWidth ? `grid-template-columns:minmax(130px,40%) 1fr ${valWidth}px` : null;
  return h('div', {}, items.map((i) => h('div', { class: 'hbar', style: cols },
    h('div', { class: 'name', title: i.title || i.name }, i.label || i.name),
    h('div', { class: 'track' }, h('div', { class: 'fill', style: `width:${Math.max(2, (i.value / top) * 100)}%;background:${i.color || color}` })),
    h('div', { class: 'val' }, i.text ?? fmt.int(i.value)))));
}
