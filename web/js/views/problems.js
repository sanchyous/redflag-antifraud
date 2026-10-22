// «Проблемы» — рискованные решения (проверка и блок) в контексте общего пула вызовов: не просто
// список инцидентов, а сколько их было относительно всего трафика, и как это распределено во времени.
// Клик по строке открывает разбор: факторы с вкладом в решение (объяснение, которого требует ТЗ).

import { openAct, downloadActPdf } from '../act.js';
import { getEvents, getRecent, getStats, getStatus } from '../api.js';
import { stackedBars } from '../charts.js';
import { factorName, isRule, signalName } from '../labels.js';
import { fmt, h, openDrawer, sevBadge, tile, toast, widget } from '../ui.js';

const STRONG = new Set(['spoof', 'unallocated_caller', 'fan']);
const COLORS = { allow: 'var(--c-good)', review: 'var(--c-review)', block: 'var(--c-block)' };

/** Пороги решения для стадии события — чтобы показать score не абстрактным числом,
 * а на фоне границы, которую он пересёк (или не пересёк). thresholds — { stage1: {review,block}, ml: {review,block} }. */
function stageThresholds(e, thresholds) {
  if (!thresholds) return null;
  return e.stage === 'ml' ? thresholds.ml : thresholds.stage1;
}

function scoreWithThreshold(e, thresholds) {
  const t = stageThresholds(e, thresholds);
  if (!t) return e.score.toFixed(4);
  const near = e.decision === 'block' ? t.block : t.review;
  return `${e.score.toFixed(4)} (порог ${e.decision === 'block' ? 'блока' : 'проверки'} ${near.toFixed(4)})`;
}

/** Содержит ли вызов искомые цифры номера (звонящий или получатель). */
function matchesQuery(e, query) {
  const digits = query.replace(/\D/g, '');
  if (!digits) return true;
  const strip = (s) => (s || '').replace(/\D/g, '');
  return strip(e.caller).includes(digits) || strip(e.callee).includes(digits);
}

/** Таблица событий. compact — без столбца стадии и времени в полном виде. thresholds — см. scoreWithThreshold. */
export function eventTable(items, { compact = false, thresholds } = {}) {
  const head = h('tr', {}, h('th', {}, 'Время'), h('th', {}, 'Серьёзность'), h('th', {}, 'Вызов'), h('th', {}, 'Причина'),
    h('th', { class: 'num' }, 'Score'), compact ? null : h('th', {}, 'Стадия'), compact ? null : h('th', {}, 'Сигналы'));
  const rows = items.map((e) => {
    const top = (e.reasons || []).find((r) => r.effect === 'raises');
    return h('tr', { class: 'row', onclick: () => openEvent(e, thresholds) },
      h('td', { class: 'muted', title: fmt.dateTime(e.time) }, compact ? fmt.ago(e.time) : fmt.dateTime(e.time)),
      h('td', {}, sevBadge(e.decision)),
      h('td', {}, h('div', { class: 'mono' }, `${e.caller} → ${e.callee}`), h('div', { class: 'muted', style: 'font-size:12px' }, regionLine(e))),
      h('td', {}, top ? top.text : '—', e.rule_floor ? h('span', { class: 'chip hot', title: 'вердикт поднят жёстким правилом' }, 'правило') : null),
      h('td', { class: 'num' }, e.score.toFixed(4)),
      compact ? null : h('td', {}, e.stage === 'ml' ? 'ML' : 'линейная'),
      compact ? null : h('td', {}, (e.signals || []).map((s) => h('span', { class: 'chip' + (STRONG.has(s) ? ' hot' : '') }, signalName(s)))));
  });
  return h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, head), h('tbody', {}, rows)));
}

/** Таблица общего пула из журнала Postgres: схема беднее, чем у /v1/events (нет стадии, регионов,
 * сводки) — решения там не только рискованные, allow попадает выборочно, не весь поток. */
function recentTable(items) {
  const head = h('tr', {}, h('th', {}, 'Время'), h('th', {}, 'Серьёзность'), h('th', {}, 'Вызов'), h('th', {}, 'Причина'), h('th', { class: 'num' }, 'Score'));
  const rows = items.map((e) => {
    const top = (e.reasons || []).find((r) => r.effect === 'raises');
    return h('tr', { class: 'row' },
      h('td', { class: 'muted', title: fmt.dateTime(e.created_at) }, fmt.ago(e.created_at)),
      h('td', {}, sevBadge(e.decision)),
      h('td', { class: 'mono' }, `${e.caller} → ${e.callee}`),
      h('td', {}, top ? top.text : '—'),
      h('td', { class: 'num' }, e.score.toFixed(4)));
  });
  return h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, head), h('tbody', {}, rows)));
}

function regionLine(e) {
  const a = e.caller_region || '?';
  const b = e.callee_region || '?';
  return `${a} → ${b}`;
}

/** Панель разбора: решение, сигналы и вклад каждого фактора (полоса вправо — повышает риск, влево — снижает). */
export function openEvent(e, thresholds) {
  const reasons = e.reasons || [];
  const maxAbs = Math.max(0.01, ...reasons.map((r) => Math.abs(r.contribution)));
  const contrib = h('div', {}, reasons.map((r) => {
    const w = (Math.abs(r.contribution) / maxAbs) * 50;
    const up = r.contribution >= 0;
    return h('div', { style: 'margin:10px 0' },
      h('div', { style: 'display:flex;justify-content:space-between;gap:10px;font-size:13px' },
        h('span', {}, isRule(r.factor) ? h('b', {}, r.text) : [h('b', {}, factorName(r.factor)), h('span', { class: 'muted' }, ' — ' + r.text)]),
        h('span', { class: 'mono', style: `color:${up ? 'var(--c-block)' : 'var(--c-good)'}` }, r.contribution === 0 ? 'правило' : fmt.signed(r.contribution))),
      h('div', { style: 'position:relative;height:10px;background:var(--panel-head);border:1px solid var(--line);border-radius:5px;margin-top:4px' },
        h('div', { style: 'position:absolute;left:50%;top:0;bottom:0;width:1px;background:var(--line)' }),
        h('div', { style: `position:absolute;top:0;bottom:0;border-radius:5px;background:${up ? 'var(--c-block)' : 'var(--c-good)'};${up ? 'left:50%;' : `right:50%;`}width:${w}%` })));
  }));
  const kv = h('dl', { class: 'kv' },
    h('dt', {}, 'Решение'), h('dd', {}, sevBadge(e.decision)),
    h('dt', {}, 'Score'), h('dd', {}, scoreWithThreshold(e, thresholds)),
    h('dt', {}, 'Стадия'), h('dd', {}, e.stage === 'ml' ? 'ML (CatBoost) — вклад факторов посчитан SHAP, не точной формулой' : 'линейная модель — вклад факторов посчитан точно'),
    h('dt', {}, 'Вызов'), h('dd', { class: 'mono' }, `${e.caller} → ${e.callee}`),
    h('dt', {}, 'Регионы'), h('dd', {}, regionLine(e)),
    h('dt', {}, 'Идентификатор'), h('dd', { class: 'mono' }, e.call_id),
    h('dt', {}, 'Время'), h('dd', {}, fmt.dateTime(e.time)),
    h('dt', {}, 'Сигналы'), h('dd', {}, (e.signals || []).length ? e.signals.map((s) => h('span', { class: 'chip hot' }, signalName(s))) : '—'),
    h('dt', {}, 'Задержка'), h('dd', {}, fmt.us(e.latency_us)),
    e.rule_floor ? h('dt', {}, 'Пол-правило') : null,
    e.rule_floor ? h('dd', {}, (reasons.find((r) => isRule(r.factor)) || {}).text || 'Вердикт поднят жёстким правилом независимо от модели.') : null,
    e.block_suppressed ? h('dt', {}, 'Защита') : null,
    e.block_suppressed ? h('dd', {}, 'Блок заменён проверкой: защитный класс.') : null);
  openDrawer('Разбор решения', h('div', {}, e.summary ? h('p', { style: 'margin:0 0 14px;line-height:1.45' }, e.summary) : null, kv,
    h('div', { style: 'display:flex;gap:8px;margin:10px 0' },
      h('button', { class: 'btn ghost small', type: 'button', onclick: () => openAct(e).catch((err) => toast(err.message, true)) }, 'Сформировать акт для надзорного органа'),
      h('button', { class: 'btn ghost small', type: 'button', onclick: () => downloadActPdf(e).catch((err) => toast(err.message, true)) }, 'Скачать PDF')),
    h('h3', { style: 'margin:18px 0 4px;font-size:14px' }, 'Факторы'),
    h('div', { class: 'muted', style: 'font-size:12px' }, 'вправо — повышает риск, влево — снижает'), contrib));
}

export async function render(root, ctx) {
  const filter = ctx.problemsFilter || '';
  const tab = ctx.problemsTab || 'problems';
  const query = ctx.problemsQuery || '';
  const points = 60;
  const [data, status, stats] = await Promise.all([getEvents(200, filter), getStatus(), getStats(ctx.windowSec, points)]);
  const thresholds = { stage1: status.engine.stage1, ml: status.engine.ml };
  const t = stats.totals;
  const total = t.total || 0;

  // Общий пул: не только список проблем, а их доля от всего, что прошло через систему за то же окно.
  const summary = h('div', { class: 'grid cols-4' },
    tile(`Всего за ${ctx.windowLabel}`, fmt.int(total), 'общий пул вызовов', 'info'),
    tile('Проверка', fmt.int(t.review), total ? fmt.pct(t.review / total, 2) : '—', t.review ? 'avg' : 'ok'),
    tile('Блок', fmt.int(t.block), total ? fmt.pct(t.block / total, 2) : '—', t.block ? 'high' : 'ok'),
    tile('Пропущено', fmt.int(t.allow), total ? fmt.pct(t.allow / total, 1) : '—', ''));

  const trend = widget('Решения по времени', stackedBars(stats.points, [
    { key: 'allow', color: COLORS.allow, label: 'Пропуск' }, { key: 'review', color: COLORS.review, label: 'Проверка' }, { key: 'block', color: COLORS.block, label: 'Блок' },
  ]), { sub: `шаг ${stats.step_sec} с` });

  const tabBtn = (value, label) => h('button', {
    class: 'btn small' + (tab === value ? '' : ' ghost'), style: 'margin-right:6px',
    onclick: () => { ctx.problemsTab = value; ctx.rerender(); },
  }, label);
  const filterBtn = (value, label) => h('button', {
    class: 'btn small' + (filter === value ? '' : ' ghost'), style: 'margin-right:6px',
    onclick: () => { ctx.problemsFilter = value; ctx.rerender(); },
  }, label);
  const search = h('input', {
    class: 'search-input', type: 'search', placeholder: 'Поиск по номеру…', value: query,
    oninput: (e) => { ctx.problemsQuery = e.target.value; },
    onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); ctx.rerender(); } },
  });

  let body;
  if (tab === 'pool') {
    if (!status.store.enabled) {
      body = widget('Общий пул вызовов', h('div', { class: 'empty' }, 'Журнал (Postgres) недоступен — общий пул не сохраняется.'));
    } else {
      const recent = await getRecent(150, '');
      const items = (recent.items || []).filter((e) => matchesQuery(e, query));
      body = widget('Общий пул вызовов',
        items.length ? recentTable(items) : h('div', { class: 'empty' }, query ? 'Ничего не найдено' : 'Журнал пуст.'),
        { sub: 'из журнала Postgres — allow попадает выборочно, не весь поток', flush: true });
    }
  } else {
    const items = data.items.filter((e) => matchesQuery(e, query));
    body = widget('Рискованные вызовы',
      items.length ? eventTable(items, { thresholds }) : h('div', { class: 'empty' }, query ? 'Ничего не найдено' : 'Рискованных вызовов нет'),
      { sub: h('span', {}, filterBtn('', 'все'), filterBtn('block', 'блокировки'), filterBtn('review', 'проверки')), flush: true });
  }

  root.replaceChildren(
    summary,
    h('div', { style: 'margin-top:14px' }, trend),
    h('div', { class: 'problems-toolbar', style: 'margin-top:14px' },
      h('div', {}, tabBtn('problems', 'Проблемы'), tabBtn('pool', 'Общий пул')),
      search),
    h('div', { style: 'margin-top:10px' }, body));
}
