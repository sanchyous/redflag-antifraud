// Точка входа панели: навигация (hash-роутер), выбор интервала, автообновление, индикатор связи.

import { ApiError, getKey, getStatus, setKey } from './api.js';
import { h, toast } from './ui.js';
import * as components from './views/components.js';
import * as dashboard from './views/dashboard.js';
import * as graph from './views/graph.js';
import * as model from './views/model.js';
import * as playground from './views/playground.js';
import * as problems from './views/problems.js';

const ROUTES = [
  { path: 'dashboard', title: 'Панель', icon: '▦', group: 'Мониторинг', view: dashboard, live: true },
  { path: 'problems', title: 'Проблемы', icon: '⚠', group: 'Мониторинг', view: problems, badge: true, live: true },
  { path: 'components', title: 'Компоненты', icon: '◉', group: 'Мониторинг', view: components, live: true },
  { path: 'graph', title: 'Граф связей', icon: '⌬', group: 'Аналитика', view: graph, live: true },
  { path: 'model', title: 'Модель', icon: '∑', group: 'Аналитика', view: model },
  { path: 'playground', title: 'Проверка вызова', icon: '▶', group: 'Инструменты', view: playground },
];

const RANGES = [
  { label: '5 мин', sec: 300 },
  { label: '15 мин', sec: 900 },
  { label: '1 час', sec: 3600 },
  { label: '24 часа', sec: 86400 },
];

const ctx = { windowSec: 900, windowLabel: '15 мин', problemsFilter: '', rerender: () => render(true) };

const $ = (id) => document.getElementById(id);
let timer = null;
let inflight = false;

function currentRoute() {
  const path = (location.hash || '#/dashboard').replace(/^#\//, '').split('?')[0];
  return ROUTES.find((r) => r.path === path) || ROUTES[0];
}

function buildNav() {
  const nav = $('nav');
  nav.replaceChildren();
  let group = '';
  for (const r of ROUTES) {
    if (r.group !== group) {
      group = r.group;
      nav.append(h('div', { class: 'nav-group' }, group));
    }
    nav.append(h('a', { class: 'nav-item', href: '#/' + r.path, 'data-path': r.path, onclick: () => $('sidebar').classList.remove('open') },
      h('span', {}, r.icon), h('span', {}, r.title), r.badge ? h('span', { class: 'badge', id: 'nav-badge', hidden: true }, '0') : null));
  }
}

function buildRange() {
  const box = $('range');
  box.replaceChildren(...RANGES.map((r) => h('button', {
    class: r.sec === ctx.windowSec ? 'active' : '', type: 'button',
    onclick: () => { ctx.windowSec = r.sec; ctx.windowLabel = r.label; buildRange(); render(true); },
  }, r.label)));
}

function setConnection(ok, text) {
  const c = $('conn');
  c.className = 'conn ' + (ok ? 'ok' : 'bad');
  $('conn-text').textContent = text;
}

function askKey() {
  const key = window.prompt('Введите ключ доступа к API (X-API-Key):', getKey());
  if (key === null) return false;
  setKey(key.trim());
  return true;
}

async function render(force = false) {
  if (inflight && !force) return;
  const route = currentRoute();
  // Экраны без «живых» данных (проверка вызова, модель) по таймеру не перерисовываются: иначе обновление
  // стёрло бы результат, пока пользователь его читает. Ручная перерисовка (force) работает всегда.
  if (!force && !route.live) return;
  inflight = true;
  document.querySelectorAll('.nav-item').forEach((a) => a.classList.toggle('active', a.dataset.path === route.path));
  $('page-title').textContent = route.title;
  document.title = `${route.title} — RedFlag`;
  $('range').style.display = route.path === 'dashboard' ? '' : 'none';
  try {
    const box = document.createElement('div');
    await route.view.render(box, ctx);
    $('content').replaceChildren(...box.childNodes);
    setConnection(true, 'на связи');
    updateFoot();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      setConnection(false, 'нужен ключ');
      $('content').replaceChildren(h('div', { class: 'widget' }, h('div', { class: 'empty' },
        'API защищён ключом. ', h('button', { class: 'btn small', onclick: () => { if (askKey()) render(true); } }, 'Ввести ключ'))));
    } else {
      setConnection(false, e.message || 'ошибка');
      if (!$('content').children.length) $('content').replaceChildren(h('div', { class: 'widget' }, h('div', { class: 'empty' }, `Не удалось получить данные: ${e.message}`)));
      else toast('Ошибка обновления: ' + e.message, true);
    }
  } finally {
    inflight = false;
  }
}

async function updateFoot() {
  try {
    const s = await getStatus();
    $('sidebar-foot').textContent = `v${s.service.version} · работает ${Math.floor(s.service.uptime_sec / 60)} мин`;
    const bad = s.totals.block;
    const badge = $('nav-badge');
    if (badge) { badge.textContent = String(bad > 99 ? '99+' : bad); badge.hidden = !bad; }
  } catch { /* индикатор связи уже показывает проблему */ }
}

function schedule() {
  clearInterval(timer);
  if ($('auto').checked) timer = setInterval(() => render(), 3000);
}

function init() {
  buildNav();
  buildRange();
  $('auto').addEventListener('change', schedule);
  $('key-btn').addEventListener('click', () => { if (askKey()) render(true); });
  $('menu-btn').addEventListener('click', () => $('sidebar').classList.toggle('open'));
  window.addEventListener('hashchange', () => render(true));
  document.addEventListener('visibilitychange', () => { if (!document.hidden) render(true); });
  schedule();
  render(true);
}

init();
